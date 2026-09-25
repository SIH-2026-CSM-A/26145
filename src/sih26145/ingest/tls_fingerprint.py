"""Cleartext TLS handshake parsing and fingerprints: JA3, JA4 (client) and JA3S (server).

Reads only the unencrypted ClientHello / ServerHello records. Nothing here decrypts.
JA3/JA3S: https://github.com/salesforce/ja3 (BSD-3). JA4: FoxIO technical_details/JA4.md
(BSD-3). JA4S and the rest of JA4+ are under the FoxIO licence and are not implemented.
"""

import hashlib
import struct
from dataclasses import dataclass, field
from typing import List, Optional

_TLS_VERSIONS = {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3",
                 0x0002: "s2", 0xFEFF: "d1", 0xFEFD: "d2", 0xFEFC: "d3"}
_LEGACY_NAMES = {0x0303: "TLS 1.2", 0x0302: "TLS 1.1", 0x0301: "TLS 1.0"}
EXT_SNI, EXT_CURVES, EXT_POINT_FORMATS, EXT_SIG_ALGS, EXT_ALPN, EXT_SUPPORTED_VERSIONS = 0, 10, 11, 13, 16, 43


def is_grease(v: int) -> bool:
    """RFC 8701 GREASE values: 0x0a0a, 0x1a1a, ... 0xfafa."""
    return (v & 0x0F0F) == 0x0A0A and (v >> 8) == (v & 0xFF)


@dataclass
class Hello:
    """Fields of a ClientHello (is_client) or ServerHello, as they appear on the wire."""
    is_client: bool
    legacy_version: int
    ciphers: List[int] = field(default_factory=list)       # server: the one chosen cipher
    extensions: List[int] = field(default_factory=list)    # in wire order
    sni: Optional[str] = None
    curves: List[int] = field(default_factory=list)
    point_formats: List[int] = field(default_factory=list)
    alpn: List[bytes] = field(default_factory=list)
    sig_algs: List[int] = field(default_factory=list)
    supported_versions: List[int] = field(default_factory=list)

    @property
    def version_name(self) -> str:
        return _LEGACY_NAMES.get(self.legacy_version, f"{self.legacy_version >> 8}.{self.legacy_version & 0xFF}")


def _u16_list(b: bytes) -> List[int]:
    return [struct.unpack("!H", b[i:i + 2])[0] for i in range(0, len(b) - 1, 2)]


def _parse_extension(h: Hello, ext_type: int, data: bytes) -> None:
    if ext_type == EXT_SNI and len(data) >= 5 and data[2] == 0:
        name_len = struct.unpack("!H", data[3:5])[0]
        try:
            h.sni = data[5:5 + name_len].decode("ascii")
        except UnicodeDecodeError:
            pass
    elif ext_type == EXT_CURVES and len(data) >= 2:
        h.curves = _u16_list(data[2:2 + struct.unpack("!H", data[:2])[0]])
    elif ext_type == EXT_POINT_FORMATS and data:
        h.point_formats = list(data[1:1 + data[0]])
    elif ext_type == EXT_SIG_ALGS and len(data) >= 2:
        h.sig_algs = _u16_list(data[2:2 + struct.unpack("!H", data[:2])[0]])
    elif ext_type == EXT_ALPN and len(data) >= 2:
        pos, end = 2, 2 + struct.unpack("!H", data[:2])[0]
        while pos < min(end, len(data)):
            n = data[pos]
            h.alpn.append(bytes(data[pos + 1:pos + 1 + n]))
            pos += 1 + n
    elif ext_type == EXT_SUPPORTED_VERSIONS:
        # ClientHello: 1-byte list length + u16 list. ServerHello: a single u16.
        h.supported_versions = _u16_list(data[1:1 + data[0]]) if h.is_client and data else _u16_list(data[:2])


def parse_hello(payload: bytes) -> Optional[Hello]:
    """Parse a TLS record carrying a ClientHello or ServerHello. None if it is neither.

    Truncated records yield whatever fields were complete before the cut.
    """
    if not isinstance(payload, (bytes, bytearray)) or len(payload) < 9 or payload[0] != 22:
        return None
    record_len = struct.unpack("!H", payload[3:5])[0]
    hs = payload[5:5 + record_len]
    if len(hs) < 6 or hs[0] not in (1, 2):
        return None
    h = Hello(is_client=hs[0] == 1, legacy_version=struct.unpack("!H", hs[4:6])[0])
    pos = 6 + 32  # skip random
    try:
        pos += 1 + hs[pos]  # session id
        if h.is_client:
            n = struct.unpack("!H", hs[pos:pos + 2])[0]
            if pos + 2 + n > len(hs):
                return h
            h.ciphers = _u16_list(hs[pos + 2:pos + 2 + n])
            pos += 2 + n
            pos += 1 + hs[pos]  # compression methods
        else:
            h.ciphers = [struct.unpack("!H", hs[pos:pos + 2])[0]]
            pos += 3  # cipher + compression method
        ext_end = min(len(hs), pos + 2 + struct.unpack("!H", hs[pos:pos + 2])[0])
        pos += 2
        while pos + 4 <= ext_end:
            ext_type, ext_len = struct.unpack("!HH", hs[pos:pos + 4])
            pos += 4
            h.extensions.append(ext_type)
            if pos + ext_len <= ext_end:
                _parse_extension(h, ext_type, bytes(hs[pos:pos + ext_len]))
            pos += ext_len
    except (IndexError, struct.error):
        pass  # truncated: keep what was parsed
    return h


def _dash(values) -> str:
    return "-".join(str(v) for v in values if not is_grease(v))


def ja3_string(h: Hello) -> str:
    return ",".join([str(h.legacy_version), _dash(h.ciphers), _dash(h.extensions),
                     _dash(h.curves), _dash(h.point_formats)])


def ja3(h: Hello) -> str:
    return hashlib.md5(ja3_string(h).encode()).hexdigest()


def ja3s(h: Hello) -> str:
    s = ",".join([str(h.legacy_version), _dash(h.ciphers), _dash(h.extensions)])
    return hashlib.md5(s.encode()).hexdigest()


def _alpn_chars(alpn: List[bytes]) -> str:
    if not alpn or not alpn[0]:
        return "00"
    first, last = alpn[0][0], alpn[0][-1]
    if chr(first).isalnum() and chr(last).isalnum() and first < 128 and last < 128:
        return chr(first) + chr(last)
    hx = alpn[0].hex()
    return hx[0] + hx[-1]


def _hash12(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()[:12]


def ja4(h: Hello, transport: str = "t") -> str:
    """JA4 client fingerprint: a_b_c per the FoxIO specification."""
    versions = [v for v in h.supported_versions if not is_grease(v)]
    version = _TLS_VERSIONS.get(max(versions) if versions else h.legacy_version, "00")
    ciphers = [c for c in h.ciphers if not is_grease(c)]
    exts = [e for e in h.extensions if not is_grease(e)]
    a = (f"{transport}{version}{'d' if EXT_SNI in exts else 'i'}"
         f"{min(len(ciphers), 99):02d}{min(len(exts), 99):02d}{_alpn_chars(h.alpn)}")
    b = _hash12(",".join(sorted(f"{c:04x}" for c in ciphers))) if ciphers else "000000000000"
    ext_list = sorted(f"{e:04x}" for e in exts if e not in (EXT_SNI, EXT_ALPN))
    if not ext_list:
        c = "000000000000"
    else:
        c_raw = ",".join(ext_list)
        sigs = [s for s in h.sig_algs if not is_grease(s)]
        if sigs:
            c_raw += "_" + ",".join(f"{s:04x}" for s in sigs)
        c = _hash12(c_raw)
    return f"{a}_{b}_{c}"
