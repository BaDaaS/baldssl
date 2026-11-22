#!/usr/bin/env python3
"""Writes certificates whose version field takes the values OpenSSL reads
but DER does not produce, for the interop and unit tests.

Usage: gen-version-certs.py <source.crt> <output-dir>

Each output is the source certificate with its TBSCertificate's version
field replaced (absent, or [0] EXPLICIT INTEGER with the given contents)
and the lengths re-encoded. The signature is not recomputed: x509 -text
does not verify it. Lengths are DER definite lengths, big-endian.
"""

import base64
import sys
from pathlib import Path

# Name suffix -> INTEGER contents (two's complement, big-endian), or None
# for an absent field.
VERSIONS = {
    "absent": None,
    "explicit-v1": "00",
    "3": "03",
    "minus1": "ff",
    "i64max": "7fffffffffffffff",
    "toolarge": "008000000000000000",
}


def header(data: bytes, i: int) -> tuple[int, int, int]:
    """(tag, contents start, contents end) of the TLV at offset i."""
    tag, length = data[i], data[i + 1]
    start = i + 2
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(data[start : start + n], "big")
        start += n
    return tag, start, start + length


def tlv(tag: int, contents: bytes) -> bytes:
    n = len(contents)
    if n < 0x80:
        return bytes([tag, n]) + contents
    size = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(size)]) + size + contents


def pem(der: bytes) -> str:
    b64 = base64.b64encode(der).decode()
    lines = [b64[i : i + 64] for i in range(0, len(b64), 64)]
    body = "\n".join(lines)
    return f"-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n"


def main() -> None:
    source, out = Path(sys.argv[1]), Path(sys.argv[2])
    text = source.read_text()
    b64 = "".join(
        line for line in text.splitlines() if not line.startswith("-----")
    )
    cert = base64.b64decode(b64)
    _, cert_start, cert_end = header(cert, 0)
    _, tbs_start, tbs_end = header(cert, cert_start)
    tbs = cert[tbs_start:tbs_end]
    tag, _, version_end = header(tbs, 0)
    if tag != 0xA0:
        sys.exit("the source certificate has no version field")
    after = cert[tbs_end:cert_end]
    for name, contents in VERSIONS.items():
        field = (
            b""
            if contents is None
            else tlv(0xA0, tlv(0x02, bytes.fromhex(contents)))
        )
        new_tbs = tlv(0x30, field + tbs[version_end:])
        der = tlv(0x30, new_tbs + after)
        (out / f"p256-version-{name}.crt").write_text(pem(der))


if __name__ == "__main__":
    main()
