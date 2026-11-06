"""复现独立的算法测试和端到端代理性能测量。"""

import asyncio
import json
import math
import platform
import ssl
from statistics import median
from time import perf_counter

from crypto_lab import AES128, rsa_modexp, square_and_multiply
from demo import PAYLOAD, exchange, start_stack


def time_operation(operation, repeat=7):
    durations = []
    operation()
    for _ in range(repeat):
        start = perf_counter()
        operation()
        durations.append(perf_counter() - start)
    return round(median(durations) * 1000, 3)


def algorithms():
    data = PAYLOAD[:16 * 1024]
    reference = AES128(bytes(range(16)), use_tables=False)
    optimized = AES128(bytes(range(16)))
    encrypted = reference.transform_blocks(data)
    assert optimized.transform_blocks(data) == encrypted
    assert optimized.transform_blocks(encrypted, decrypt=True) == data
    modulus = (1 << 2048) - 159
    exponent = (1 << 2047) + (int.from_bytes(bytes(range(256))) >> 1)
    base = int.from_bytes(PAYLOAD[:256])
    assert rsa_modexp(base, exponent, modulus) == square_and_multiply(base, exponent, modulus)
    return {
        "aes_16KiB_median_ms": {
            "encrypt_arithmetic": time_operation(lambda: reference.transform_blocks(data)),
            "encrypt_tables": time_operation(lambda: optimized.transform_blocks(data)),
            "decrypt_arithmetic": time_operation(lambda: reference.transform_blocks(encrypted, decrypt=True)),
            "decrypt_tables": time_operation(lambda: optimized.transform_blocks(encrypted, decrypt=True)),
        },
        "rsa_2048bit_modexp_median_ms": {
            "square_and_multiply": time_operation(lambda: square_and_multiply(base, exponent, modulus)),
            "pow": time_operation(lambda: rsa_modexp(base, exponent, modulus)),
        },
    }


async def proxy():
    results = {}
    requests = 24
    async with start_stack() as (port, authority, _):
        async def fetch():
            begin = perf_counter()
            response, body = await exchange(port, authority, b"/blob")
            if response.status_code != 200 or body != PAYLOAD:
                raise RuntimeError("Proxy returned an invalid response")
            return (perf_counter() - begin) * 1000

        for concurrency in (1, 8):
            await asyncio.gather(*(fetch() for _ in range(concurrency)))
            samples = []
            begin = perf_counter()
            for _ in range(requests // concurrency):
                samples.extend(await asyncio.gather(*(fetch() for _ in range(concurrency))))
            elapsed = perf_counter() - begin
            results[str(concurrency)] = {
                "requests": requests,
                "bytes_per_response": len(PAYLOAD),
                "aggregate_MiB_s": round(requests * len(PAYLOAD) / (elapsed * 2**20), 2),
                "median_ms": round(median(samples), 2),
                "p95_ms": round(sorted(samples)[math.ceil(0.95 * requests) - 1], 2),
            }
    return results


if __name__ == "__main__":
    print(json.dumps({
        "platform": platform.system() + " " + platform.release() + " " + platform.machine(),
        "python": platform.python_version(),
        "openssl": ssl.OPENSSL_VERSION,
        "algorithm_runs": 7,
        **algorithms(),
        "proxy_by_concurrency": asyncio.run(proxy()),
    }, indent=2))
