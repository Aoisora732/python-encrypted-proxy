"""为测试和性能测量提供返回固定内容的本地源站及临时证书。"""

import argparse
import asyncio
from contextlib import AsyncExitStack, asynccontextmanager
from pathlib import Path
import subprocess
import tempfile
from urllib.parse import urlsplit

import h11

from proxy import CHUNK, LOOPBACK, client_tls, close, http_event, local_handler, relay_handler, send, server_tls

PAYLOAD = bytes(range(256)) * 4096


def make_cert(directory, name):
    cert = str(Path(directory, name + ".crt"))
    key = str(Path(directory, name + ".key"))
    config = Path(directory, "openssl.cnf")
    config.write_text("[req]\ndistinguished_name = dn\n[dn]\n", encoding="ascii")
    result = subprocess.run([
        "openssl", "req", "-config", str(config), "-x509", "-newkey", "rsa:2048", "-sha256", "-nodes",
        "-days", "2", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
        "-keyout", key, "-out", cert,
    ], capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(f"OpenSSL certificate generation failed: {result.stderr.strip()}")
    return cert, key


async def origin(reader, writer):
    connection = h11.Connection(h11.SERVER)
    try:
        request = await http_event(connection, lambda: reader.read(CHUNK))
        if not isinstance(request, h11.Request):
            return
        body = bytearray()
        while isinstance(event := await http_event(connection, lambda: reader.read(CHUNK)), h11.Data):
            body.extend(event.data)
        if not isinstance(event, h11.EndOfMessage):
            return
        path = urlsplit(request.target).path
        if path == b"/slow":
            await asyncio.sleep(0.12)
        status = 404 if path == b"/missing" else 200
        payload = bytes(body) if request.method == b"POST" else PAYLOAD if path == b"/blob" else request.target
        headers = [(b"content-type", b"application/octet-stream"), (b"x-origin", b"fixture")]
        if path != b"/blob":
            headers.append((b"content-length", str(len(payload)).encode()))
        await send(writer, connection.send(h11.Response(status_code=status, headers=headers)))
        if request.method != b"HEAD":
            for offset in range(0, len(payload), CHUNK):
                await send(writer, connection.send(h11.Data(data=payload[offset:offset + CHUNK])))
        await send(writer, connection.send(h11.EndOfMessage()))
    finally:
        await close(writer)


def port(listener):
    return listener.sockets[0].getsockname()[1]


@asynccontextmanager
async def start_stack(*, tls_origin=False, wrong_hostname=False, untrusted=False, mutual_tls=False,
                      send_client_cert=True):
    with tempfile.TemporaryDirectory() as directory:
        cert, key = await asyncio.to_thread(make_cert, directory, "relay")
        origin_cert = None
        origin_context = None
        if tls_origin:
            origin_cert, origin_key = await asyncio.to_thread(make_cert, directory, "origin")
            origin_context = server_tls(origin_cert, origin_key)
        trust = (await asyncio.to_thread(make_cert, directory, "untrusted"))[0] if untrusted else cert
        client_cert, client_key = (
            await asyncio.to_thread(make_cert, directory, "client") if mutual_tls else (None, None)
        )
        async with AsyncExitStack() as stack:
            upstream = await stack.enter_async_context(await asyncio.start_server(
                origin, LOOPBACK, 0, ssl=origin_context,
            ))
            relay = await stack.enter_async_context(await asyncio.start_server(
                relay_handler(LOOPBACK, port(upstream)), LOOPBACK, 0, ssl=server_tls(cert, key, client_cert),
            ))
            authority = f"{LOOPBACK}:{port(upstream)}".encode()
            proxy = await stack.enter_async_context(await asyncio.start_server(
                local_handler(
                    LOOPBACK, port(relay), "wrong.test" if wrong_hostname else "localhost",
                    client_tls(trust, client_cert if send_client_cert else None, client_key), authority,
                ), LOOPBACK, 0,
            ))
            yield port(proxy), authority, origin_cert


async def exchange(proxy_port, authority, path, method=b"GET", body=b""):
    reader, writer = await asyncio.open_connection(LOOPBACK, proxy_port)
    conn = h11.Connection(h11.CLIENT)
    try:
        request = h11.Request(
            method=method, target=b"http://" + authority + path,
            headers=[(b"host", authority), (b"content-length", str(len(body)).encode())],
        )
        await send(writer, conn.send(request))
        for offset in range(0, len(body), CHUNK):
            await send(writer, conn.send(h11.Data(data=body[offset:offset + CHUNK])))
        await send(writer, conn.send(h11.EndOfMessage()))
        response = await http_event(conn, lambda: reader.read(CHUNK))
        chunks = bytearray()
        while isinstance(event := await http_event(conn, lambda: reader.read(CHUNK)), h11.Data):
            chunks.extend(event.data)
        if not isinstance(event, h11.EndOfMessage):
            raise ValueError(f"Unexpected response end: {event}")
        return response, bytes(chunks)
    finally:
        await close(writer)


if __name__ == "__main__":
    async def serve_demo(listen_port):
        async with await asyncio.start_server(origin, LOOPBACK, listen_port) as server:
            print(f"Demo origin listening on http://127.0.0.1:{port(server)}", flush=True)
            await server.serve_forever()

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--certs", type=Path, help="Generate a temporary demo certificate in a new directory")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    if args.certs:
        args.certs.mkdir()
        make_cert(args.certs, "relay")
        print(f"Demo certificate and key written to {args.certs}")
    else:
        try:
            asyncio.run(serve_demo(args.port))
        except KeyboardInterrupt:
            pass
