"""使用 TLS 保护传输的 HTTP/1.1 代理，转发至指定的上游地址。"""

import argparse
import asyncio
from contextlib import suppress
import logging
import ssl
from struct import Struct
from urllib.parse import urlsplit

import h11

CHUNK = 32 * 1024
HEADER = Struct("!BI")
READY, DATA, END, ERROR = range(1, 5)
TIMEOUT = 15
SESSION_LIMIT = 120
MAX_CONNECTIONS = 32
ALPN = "course-proxy/1"
LOOPBACK = "127.0.0.1"
LOG = logging.getLogger(__name__)
HOP_HEADERS = {
    b"connection", b"keep-alive", b"proxy-connection", b"proxy-authenticate",
    b"proxy-authorization", b"te", b"trailer", b"transfer-encoding", b"upgrade",
}


class TunnelError(Exception):
    pass


class RejectedRequest(Exception):
    def __init__(self, status):
        self.status = status


async def close(writer):
    writer.close()
    with suppress(OSError, TimeoutError):
        async with asyncio.timeout(1):
            await writer.wait_closed()


async def send(writer, data):
    if data:
        writer.write(data)
        async with asyncio.timeout(TIMEOUT):
            await writer.drain()


def encode_frame(kind, data=b""):
    if kind not in (READY, DATA, END, ERROR):
        raise TunnelError("Unknown frame type")
    if (kind == DATA and not 0 < len(data) <= CHUNK) or (kind != DATA and data):
        raise TunnelError("Invalid frame length")
    return HEADER.pack(kind, len(data)) + data


async def read_frame(reader):
    async with asyncio.timeout(TIMEOUT):
        raw_header = await reader.readexactly(HEADER.size)
        kind, size = HEADER.unpack(raw_header)
        if kind not in (READY, DATA, END, ERROR):
            raise TunnelError("Unknown frame type")
        if (kind == DATA and not 0 < size <= CHUNK) or (kind != DATA and size):
            raise TunnelError("Invalid frame length")
        return kind, await reader.readexactly(size)


async def receive_payload(reader):
    kind, payload = await read_frame(reader)
    if kind == END:
        return b""
    if kind != DATA:
        raise TunnelError("Expected data or end of stream")
    return payload


async def send_payload(writer, payload):
    for offset in range(0, len(payload), CHUNK):
        await send(writer, encode_frame(DATA, payload[offset:offset + CHUNK]))


async def raw_read(reader):
    async with asyncio.timeout(TIMEOUT):
        return await reader.read(CHUNK)


async def to_tunnel(reader, tunnel, initial=b""):
    await send_payload(tunnel, initial)
    while payload := await raw_read(reader):
        await send_payload(tunnel, payload)
    await send(tunnel, encode_frame(END))


async def from_tunnel(tunnel, writer, half_close):
    while payload := await receive_payload(tunnel):
        await send(writer, payload)
    if half_close and writer.can_write_eof():
        writer.write_eof()


async def relay_until_reply(upload, download):
    """上传正常结束后，继续等待对端发送完整的响应。"""
    up = asyncio.create_task(upload)
    down = asyncio.create_task(download)
    try:
        done, _ = await asyncio.wait((up, down), return_when=asyncio.FIRST_COMPLETED)
        if up in done:
            up.result()
        await down
    finally:
        for task in (up, down):
            task.cancel()
        await asyncio.gather(up, down, return_exceptions=True)


def require_protocol(writer):
    tls = writer.get_extra_info("ssl_object")
    if tls is None or tls.selected_alpn_protocol() != ALPN:
        raise TunnelError("TLS proxy protocol mismatch")


def server_tls(cert, key, client_ca=None):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(cert, key)
    context.set_alpn_protocols([ALPN])
    if client_ca:
        context.load_verify_locations(cafile=client_ca)
        context.verify_mode = ssl.CERT_REQUIRED
    return context


def client_tls(ca, cert=None, key=None):
    context = ssl.create_default_context(cafile=ca)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.set_alpn_protocols([ALPN])
    if cert:
        context.load_cert_chain(cert, key)
    return context


def bounded(handler):
    active = 0

    async def handle(reader, writer):
        nonlocal active
        if active >= MAX_CONNECTIONS:
            await close(writer)
            return
        active += 1
        try:
            async with asyncio.timeout(SESSION_LIMIT):
                await handler(reader, writer)
        except (OSError, EOFError, TunnelError) as exc:
            LOG.debug("Connection ended: %s", type(exc).__name__)
        finally:
            try:
                await close(writer)
            finally:
                active -= 1

    return handle


def relay_handler(upstream_host, upstream_port):
    async def handle(reader, writer):
        require_protocol(writer)
        try:
            async with asyncio.timeout(TIMEOUT):
                upstream, upstream_writer = await asyncio.open_connection(upstream_host, upstream_port)
        except OSError:
            await send(writer, encode_frame(ERROR))
            return
        try:
            await send(writer, encode_frame(READY))
            await relay_until_reply(
                from_tunnel(reader, upstream_writer, half_close=True),
                to_tunnel(upstream, writer),
            )
        finally:
            await close(upstream_writer)

    return bounded(handle)


def forward_headers(headers, *, request=False):
    blocked = HOP_HEADERS | {
        token.strip().lower()
        for name, value in headers if name == b"connection"
        for token in value.split(b",")
    }
    if request:
        blocked = blocked | {b"host", b"expect"}
    return [(key, value) for key, value in headers if key not in blocked]


def ambiguous_length(headers):
    names = {name for name, _ in headers}
    framing = {b"content-length", b"transfer-encoding"}
    connection_options = {
        token.strip().lower()
        for name, value in headers if name == b"connection"
        for token in value.split(b",")
    }
    return framing <= names or bool(framing & connection_options)


def request_target(request, authority):
    if request.method == b"CONNECT":
        if request.target.lower() != authority.lower():
            raise RejectedRequest(403)
        if any(name in (b"content-length", b"transfer-encoding") for name, _ in request.headers):
            raise RejectedRequest(400)
        return request.target
    try:
        url = urlsplit(request.target)
    except ValueError:
        raise RejectedRequest(400) from None
    if url.scheme != b"http" or url.netloc.lower() != authority.lower():
        raise RejectedRequest(403)
    if b"#" in request.target or any(byte <= 32 or byte == 127 for byte in request.target):
        raise RejectedRequest(400)
    return (url.path or b"/") + (b"?" + url.query if b"?" in request.target else b"")


async def http_event(connection, read):
    while True:
        event = connection.next_event()
        if event is not h11.NEED_DATA:
            return event
        connection.receive_data(await read())


async def send_http_error(writer, status):
    reason = {
        400: "Bad Request", 403: "Forbidden", 417: "Expectation Failed",
        501: "Not Implemented", 502: "Bad Gateway", 504: "Gateway Timeout",
    }[status]
    reply = f"HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    await send(writer, reply.encode("ascii"))


async def upload_http(incoming, outgoing, request, target, authority, local, tunnel):
    headers = forward_headers(request.headers, request=True)
    headers += [(b"host", authority), (b"connection", b"close")]
    if any(name == b"transfer-encoding" for name, _ in request.headers):
        headers.append((b"transfer-encoding", b"chunked"))
    message = h11.Request(method=request.method, target=target, headers=headers)
    await send_payload(tunnel, outgoing.send(message))
    while True:
        event = await http_event(incoming, lambda: raw_read(local))
        if isinstance(event, h11.EndOfMessage):
            await send_payload(tunnel, outgoing.send(h11.EndOfMessage()))
            await send(tunnel, encode_frame(END))
            return
        if not isinstance(event, h11.Data):
            raise RejectedRequest(400)
        await send_payload(tunnel, outgoing.send(event))


async def download_http(outgoing, incoming, tunnel, local, started):
    while True:
        event = await http_event(outgoing, lambda: receive_payload(tunnel))
        if isinstance(event, h11.InformationalResponse):
            if event.status_code == 101:
                raise TunnelError("Upgrade is outside the HTTP proxy scope")
            continue
        if isinstance(event, h11.Response):
            if ambiguous_length(event.headers):
                raise TunnelError("Upstream sent conflicting body length headers")
            headers = forward_headers(event.headers) + [(b"connection", b"close")]
            event = h11.Response(status_code=event.status_code, headers=headers, reason=event.reason)
            started.set()
        elif isinstance(event, h11.EndOfMessage):
            await send(local, incoming.send(h11.EndOfMessage()))
            return
        elif not isinstance(event, h11.Data):
            raise TunnelError("Incomplete HTTP response")
        await send(local, incoming.send(event))


def local_handler(relay_host, relay_port, server_name, context, authority):
    async def handle(reader, writer):
        inbound = h11.Connection(h11.SERVER, max_incomplete_event_size=16 * 1024)
        tunnel = None
        started = asyncio.Event()
        try:
            try:
                request = await http_event(inbound, lambda: raw_read(reader))
                if isinstance(request, h11.ConnectionClosed):
                    return
                if not isinstance(request, h11.Request):
                    raise RejectedRequest(400)
                if ambiguous_length(request.headers):
                    raise RejectedRequest(400)
                if any(name == b"upgrade" for name, _ in request.headers):
                    raise RejectedRequest(501)
                target = request_target(request, authority)
            except h11.RemoteProtocolError:
                raise RejectedRequest(400) from None
            expectations = [value.lower() for name, value in request.headers if name == b"expect"]
            if expectations and (request.method == b"CONNECT" or expectations != [b"100-continue"]):
                raise RejectedRequest(417)
            async with asyncio.timeout(TIMEOUT):
                relay, tunnel = await asyncio.open_connection(
                    relay_host, relay_port, ssl=context, server_hostname=server_name,
                    ssl_handshake_timeout=TIMEOUT, ssl_shutdown_timeout=1,
                )
            require_protocol(tunnel)
            kind, _ = await read_frame(relay)
            if kind != READY:
                raise TunnelError("Relay could not connect to the upstream")
            if request.method == b"CONNECT":
                started.set()
                await send(writer, b"HTTP/1.1 200 Connection Established\r\n\r\n")
                await relay_until_reply(
                    to_tunnel(reader, tunnel, inbound.trailing_data[0]),
                    from_tunnel(relay, writer, half_close=False),
                )
            else:
                if expectations:
                    await send(writer, inbound.send(h11.InformationalResponse(status_code=100, headers=[])))
                outbound = h11.Connection(h11.CLIENT, max_incomplete_event_size=16 * 1024)
                await relay_until_reply(
                    upload_http(inbound, outbound, request, target, authority, reader, tunnel),
                    download_http(outbound, inbound, relay, writer, started),
                )
        except RejectedRequest as exc:
            if not started.is_set():
                await send_http_error(writer, exc.status)
        except TimeoutError:
            if not started.is_set():
                await send_http_error(writer, 504)
        except (OSError, EOFError, TunnelError, h11.ProtocolError):
            if not started.is_set():
                await send_http_error(writer, 502)
        finally:
            if tunnel is not None:
                await close(tunnel)

    return bounded(handle)


def endpoint(value):
    try:
        parsed = urlsplit("//" + value)
        if parsed.path or parsed.query or parsed.fragment or parsed.username is not None:
            raise ValueError
        if not parsed.hostname or not parsed.port or parsed.netloc != value:
            raise ValueError
        value.encode("ascii")
        return parsed.hostname, parsed.port
    except ValueError:
        raise argparse.ArgumentTypeError("Expected host:port (use [address]:port for IPv6)") from None


async def run(args):
    if args.mode == "server":
        if args.bind != LOOPBACK and not args.client_ca:
            raise SystemExit("A non-loopback server requires --client-ca for mutual TLS")
        context = server_tls(args.cert, args.key, args.client_ca)
        handler = relay_handler(*args.upstream)
        listener = await asyncio.start_server(
            handler, args.bind, args.port, ssl=context,
            ssl_handshake_timeout=TIMEOUT, ssl_shutdown_timeout=1,
        )
    else:
        if bool(args.cert) != bool(args.key):
            raise SystemExit("--cert and --key must be given together")
        context = client_tls(args.ca, args.cert, args.key)
        handler = local_handler(*args.relay, args.server_name, context, args.authority.encode("ascii"))
        listener = await asyncio.start_server(handler, LOOPBACK, args.port)
    async with listener:
        print(f"{args.mode} listening on {listener.sockets[0].getsockname()}", flush=True)
        await listener.serve_forever()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest="mode", required=True)
    server = modes.add_parser("server")
    server.add_argument("--bind", default=LOOPBACK)
    server.add_argument("--port", type=int, default=7000)
    server.add_argument("--upstream", required=True, type=endpoint)
    server.add_argument("--cert", required=True)
    server.add_argument("--key", required=True)
    server.add_argument("--client-ca")
    client = modes.add_parser("client")
    client.add_argument("--port", type=int, default=7001)
    client.add_argument("--relay", type=endpoint, default=(LOOPBACK, 7000))
    client.add_argument("--server-name", default="localhost")
    client.add_argument("--ca", required=True)
    client.add_argument("--cert")
    client.add_argument("--key")
    client.add_argument("--authority", required=True, help="Allowed upstream host:port")
    args = parser.parse_args()
    if args.mode == "client":
        try:
            endpoint(args.authority)
        except argparse.ArgumentTypeError as exc:
            parser.error(str(exc))
    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
