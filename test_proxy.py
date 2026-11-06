import asyncio
import ssl
import unittest

import h11

from crypto_lab import AES128, rsa_modexp, square_and_multiply
from demo import PAYLOAD, exchange, start_stack
from proxy import (
    CHUNK, DATA, END, HEADER, LOOPBACK, RejectedRequest, TunnelError, ambiguous_length, close,
    encode_frame, forward_headers, read_frame, request_target,
)


class AlgorithmTests(unittest.TestCase):
    def test_aes_known_answer_and_inverse(self):
        # AES-128 已知答案来自 FIPS 197 原版附录 C.1。
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
        ciphertext = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
        for tables in (False, True):
            aes = AES128(key, use_tables=tables)
            self.assertEqual(aes.round_keys[1].hex(), "d6aa74fdd2af72fadaa678f1d6ab76fe")
            self.assertEqual(aes.encrypt_block(plaintext), ciphertext)
            self.assertEqual(aes.decrypt_block(ciphertext), plaintext)

    def test_aes_zero_bytes_survive_and_partial_block_is_rejected(self):
        aes = AES128(bytes(16))
        self.assertEqual(aes.encrypt_block(bytes(16)).hex(), "66e94bd4ef8a2c3b884cfa59ca342b2e")
        message = bytes(16) + bytes(range(16)) + bytes(16)
        self.assertEqual(aes.transform_blocks(aes.transform_blocks(message), decrypt=True), message)
        with self.assertRaises(ValueError):
            aes.transform_blocks(message[:-1])

    def test_rsa_arithmetic_known_answer_and_edges(self):
        for calculate in (square_and_multiply, rsa_modexp):
            self.assertEqual(calculate(65, 17, 3233), 2790)
            self.assertEqual(calculate(2790, 2753, 3233), 65)
            self.assertEqual(calculate(65, 0, 1), 0)
            with self.assertRaises(ValueError):
                calculate(65, -1, 3233)


class FrameTests(unittest.IsolatedAsyncioTestCase):
    async def test_fragmented_and_coalesced_frames(self):
        frame = encode_frame(DATA, b"\x00abc")
        reader = asyncio.StreamReader()
        task = asyncio.create_task(read_frame(reader))
        for fragment in (frame[:2], frame[2:6], frame[6:] + encode_frame(END)):
            reader.feed_data(fragment)
            await asyncio.sleep(0)
        self.assertEqual(await task, (DATA, b"\x00abc"))
        self.assertEqual(await read_frame(reader), (END, b""))

    async def test_rejects_oversized_unknown_and_truncated_frames(self):
        for header in (HEADER.pack(DATA, CHUNK + 1), HEADER.pack(100, 0)):
            reader = asyncio.StreamReader()
            reader.feed_data(header)
            with self.assertRaises(TunnelError):
                await read_frame(reader)
        reader = asyncio.StreamReader()
        reader.feed_data(HEADER.pack(DATA, 10) + b"short")
        reader.feed_eof()
        with self.assertRaises(asyncio.IncompleteReadError):
            await read_frame(reader)


class HttpRuleTests(unittest.TestCase):
    def test_absolute_uri_keeps_path_and_query(self):
        authority = b"example.test:8080"
        req = h11.Request(method=b"GET", target=b"http://example.test:8080/a%2Fb?q=x%20y",
                          headers=[(b"host", authority)])
        self.assertEqual(request_target(req, authority), b"/a%2Fb?q=x%20y")

    def test_rejects_cross_origin_and_connect_with_body(self):
        authority = b"example.test:443"
        for method, target, headers, expected in (
            (b"GET", b"http://example.test:80/", [], 403),
            (b"CONNECT", b"other.test:443", [], 403),
            (b"CONNECT", authority, [(b"content-length", b"1")], 400),
        ):
            with self.subTest(target=target), self.assertRaises(RejectedRequest) as error:
                request_target(h11.Request(method=method, target=target,
                                           headers=[(b"host", authority)] + headers), authority)
            self.assertEqual(error.exception.status, expected)

    def test_strips_hop_headers_and_rejects_ambiguous_lengths(self):
        headers = [(b"connection", b"keep-alive, X-Private"), (b"x-private", b"discard"),
                   (b"host", b"example.test"), (b"proxy-authorization", b"discard"),
                   (b"content-type", b"application/octet-stream")]
        self.assertEqual(forward_headers(headers, request=True), [headers[-1]])
        self.assertTrue(ambiguous_length([(b"content-length", b"4"), (b"transfer-encoding", b"chunked")]))
        self.assertTrue(ambiguous_length([(b"connection", b"content-length")]))


class EndToEndTests(unittest.IsolatedAsyncioTestCase):
    async def test_chunked_request_body_and_expect_continue(self):
        async with start_stack() as (port, authority, _):
            reader, writer = await asyncio.open_connection(LOOPBACK, port)
            try:
                head = (b"POST http://" + authority + b"/echo HTTP/1.1\r\nHost: " + authority
                        + b"\r\nTransfer-Encoding: chunked\r\nExpect: 100-continue\r\n\r\n")
                writer.write(head)
                await writer.drain()
                self.assertTrue((await reader.readuntil(b"\r\n\r\n")).startswith(b"HTTP/1.1 100 "))
                writer.write(b"3\r\n\x00ab\r\n2\r\nc\xff\r\n0\r\n\r\n")
                await writer.drain()
                response = await reader.read()
                self.assertTrue(response.startswith(b"HTTP/1.1 200 "))
                self.assertTrue(response.endswith(b"\x00abc\xff"))
            finally:
                await close(writer)

    async def test_mutual_tls_requires_a_client_certificate(self):
        for has_cert in (True, False):
            async with start_stack(mutual_tls=True, send_client_cert=has_cert) as (port, authority, _):
                response, body = await exchange(port, authority, b"/")
                self.assertEqual((response.status_code, body), (200, b"/") if has_cert else (502, b""))

    async def test_binary_post_large_chunked_response_and_status(self):
        async with start_stack() as (port, authority, _):
            response, body = await exchange(port, authority, b"/blob")
            self.assertEqual(response.status_code, 200)
            self.assertIn((b"x-origin", b"fixture"), response.headers)
            self.assertEqual(body, PAYLOAD)
            request_body = PAYLOAD[:3 * CHUNK] + b"\x00"
            response, body = await exchange(port, authority, b"/echo", b"POST", request_body)
            self.assertEqual((response.status_code, body), (200, request_body))
            response, body = await exchange(port, authority, b"/missing")
            self.assertEqual((response.status_code, body), (404, b"/missing"))
            response, body = await exchange(port, authority, b"/echo?x=1", b"HEAD")
            self.assertEqual((response.status_code, body), (200, b""))
            self.assertIn((b"content-length", b"9"), response.headers)

    async def test_concurrent_requests_keep_responses_isolated(self):
        async with start_stack() as (port, authority, _):
            slow = asyncio.create_task(exchange(port, authority, b"/slow"))
            fast = [asyncio.create_task(exchange(port, authority, f"/item?i={i}".encode())) for i in range(8)]
            pending = set(fast) | {slow}
            done, _ = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
            self.assertTrue(done.intersection(fast))
            self.assertEqual([body for _, body in await asyncio.gather(*fast)],
                             [f"/item?i={i}".encode() for i in range(8)])
            self.assertEqual((await slow)[1], b"/slow")

    async def test_destination_restriction_and_malformed_request(self):
        async with start_stack() as (port, _, __):
            response, body = await exchange(port, b"127.0.0.1:1234", b"/")
            self.assertEqual((response.status_code, body), (403, b""))
            reader, writer = await asyncio.open_connection(LOOPBACK, port)
            try:
                writer.write(b"GET invalid HTTP/1.1\r\nBroken header\r\n\r\n")
                await writer.drain()
                self.assertTrue((await reader.readline()).startswith(b"HTTP/1.1 400 "))
            finally:
                await close(writer)

    async def test_rejects_wrong_tls_hostname_and_untrusted_certificate(self):
        for options in ({"wrong_hostname": True}, {"untrusted": True}):
            async with start_stack(**options) as (port, authority, _):
                response, body = await exchange(port, authority, b"/")
                self.assertEqual((response.status_code, body), (502, b""))

    async def test_connect_carries_independent_https_handshake(self):
        async with start_stack(tls_origin=True) as (port, authority, cert):
            reader, writer = await asyncio.open_connection(LOOPBACK, port)
            try:
                writer.write(b"CONNECT " + authority + b" HTTP/1.1\r\nHost: " + authority + b"\r\n\r\n")
                await writer.drain()
                self.assertTrue((await reader.readuntil(b"\r\n\r\n")).startswith(b"HTTP/1.1 200 "))
                await writer.start_tls(ssl.create_default_context(cafile=cert), server_hostname="localhost")
                writer.write(b"GET /nested HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                await writer.drain()
                response = await reader.read()
                self.assertTrue(response.startswith(b"HTTP/1.1 200 "))
                self.assertTrue(response.endswith(b"/nested"))
            finally:
                await close(writer)


if __name__ == "__main__":
    unittest.main()
