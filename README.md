# Python Encrypted Proxy

A cryptography course project with encrypted TCP forwarding and unit tests.

```text
HTTP client → local proxy → framed TLS 1.3 stream → relay → configured origin
```

Each browser connection gets its own TLS connection and request state. This removes the shared socket and busy wait from the original prototype. The tradeoff is one TLS handshake per browser connection. Each direction reads at most 32 KiB of application data per frame and awaits writes, allowing a slow recipient to exert backpressure. Connections have read/write deadlines, a session deadline and a concurrency limit.

The proxy forwards absolute-form HTTP requests to one configured origin, preserving methods, status codes and binary bodies. It uses h11 to parse and reserialize HTTP/1.1. HTTPS CONNECT opens a byte tunnel to the same configured destination so the browser can negotiate its own TLS with the origin. A tunnel frame is one type byte plus a four-byte unsigned length in network order. READY and ERROR report the relay's upstream connection status. DATA carries bytes, and END marks end of input in one direction. TLS ALPN selects the framing version.

Both processes bind to loopback by default. A non-loopback relay requires a trusted client CA for mutual TLS. Configure the same destination for `--authority` and `--upstream`. This is a fixed-origin educational relay. HTTP requests use one exchange per browser connection. HTTP upgrades and arbitrary destinations are outside its scope.

## Run the local demo

Requires Python 3.11+ with TLS 1.3 support, OpenSSL on PATH, and curl for the example. From the project directory:

```sh
python -m pip install -r requirements.txt
python demo.py --certs .demo-certs
```

Run these in separate terminals:

```sh
python demo.py
python proxy.py server --upstream 127.0.0.1:8080 --cert .demo-certs/relay.crt --key .demo-certs/relay.key
python proxy.py client --authority 127.0.0.1:8080 --ca .demo-certs/relay.crt
```

```sh
curl --noproxy "" -x http://127.0.0.1:7001 http://127.0.0.1:8080/hello
```

The response body is `/hello`. Use `curl.exe` on Windows PowerShell if `curl` resolves to an alias.

## Tests and measurements

```sh
python -m unittest -v
python benchmark.py
```

| Test layer | What it checks |
| --- | --- |
| Algorithm unit tests | AES-128 known answers and inverse transform, zero-byte preservation, partial-block rejection, RSA modular exponentiation and edge cases |
| Protocol unit tests | Fragmented and coalesced frames, unknown types, oversized and truncated frames, HTTP target and header rules |
| End-to-end integration tests | HTTP GET/HEAD/POST, chunked upload and download, 1 MiB binary response, status and headers, concurrent request isolation, invalid target and HTTP rejection, certificate and hostname rejection, mTLS, and HTTPS inside CONNECT |

See [the benchmark report](BENCHMARKS.md) for measured results and methodology. [FIPS 197](https://csrc.nist.gov/pubs/fips/197/final), the [Python TLS documentation](https://docs.python.org/3/library/ssl.html), and [HTTP/1.1](https://www.rfc-editor.org/rfc/rfc9112.html) describe the underlying standards and APIs.

`crypto_lab.py` exposes AES-128 block transforms and two implementations of modular exponentiation for comparison. It uses table lookups and Python integers and is for algorithm study. The proxy uses Python's OpenSSL-backed `ssl` module for its network transport.
