"""The capture and ingest path cannot put a byte on the monitored link: no socket is created,
connected or written, no network client is imported, and every file it opens is read-only.
This is what backs the dashboard's "Bytes sent onto the monitored link: 0"."""

import ast
from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / "src" / "sih26145"
# capture -> flows -> features -> detectors, and the streaming loop that drives them.
# features/dump.py (writes the offline training CSV) is not on the capture path.
SCOPE = [*sorted((SRC / "ingest").glob("*.py")), *sorted((SRC / "flow").glob("*.py")),
         *sorted(p for p in (SRC / "features").glob("*.py") if p.name != "dump.py"),
         *sorted((SRC / "detectors").rglob("*.py")), SRC / "streaming.py"]
SEND_CALLS = {"send", "sendto", "sendall", "sendmsg", "sendfile", "connect", "connect_ex", "bind", "listen",
              "write", "writelines", "open_connection", "create_connection", "create_datagram_endpoint"}
SOCKET_FACTORIES = {"socket", "socketpair", "fromfd", "create_connection", "create_server"}
NETWORK_MODULES = {"urllib", "http", "requests", "httpx", "aiohttp", "ftplib", "smtplib", "telnetlib", "scapy"}


def violations(source: str, name: str = "<src>") -> list:
    out = []
    for n in ast.walk(ast.parse(source)):
        if isinstance(n, (ast.Import, ast.ImportFrom)):
            mods = [a.name for a in n.names] if isinstance(n, ast.Import) else [n.module or ""]
            out += [f"{name}:{n.lineno} imports {m}" for m in mods if m.split(".")[0] in NETWORK_MODULES]
        elif isinstance(n, ast.Call):
            f = n.func
            attr = f.attr if isinstance(f, ast.Attribute) else f.id if isinstance(f, ast.Name) else None
            if attr in SEND_CALLS:
                out.append(f"{name}:{n.lineno} calls .{attr}()")
            if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and f.value.id == "socket" \
                    and f.attr in SOCKET_FACTORIES:
                out.append(f"{name}:{n.lineno} creates a socket")
            if attr == "open":
                mode = n.args[1] if len(n.args) > 1 else next((k.value for k in n.keywords if k.arg == "mode"), None)
                ok = mode is None or (isinstance(mode, ast.Constant) and isinstance(mode.value, str)
                                      and mode.value.startswith("r") and "+" not in mode.value)
                if not ok:
                    out.append(f"{name}:{n.lineno} opens a file for writing")
    return out


def test_capture_path_has_no_transmit_and_opens_read_only():
    found = [v for p in SCOPE for v in violations(p.read_text(), p.relative_to(SRC).as_posix())]
    assert found == [], found
    assert SRC / "ingest" / "reader.py" in SCOPE and len(SCOPE) > 10


def test_the_scan_catches_what_it_forbids():
    """Falsification: each forbidden pattern, injected, is reported."""
    for bad in ("import socket\ns = socket.socket()\n", "sock.sendto(b'x', ('10.0.0.1', 9))\n",
                "f = open('/dev/net', 'wb')\n", "open(p, mode='a')\n", "import urllib.request\n",
                "writer.write(b'x')\n", "open(p, 'r+')\n"):
        assert violations(bad), bad
    assert violations("import socket\nip = socket.inet_ntop(socket.AF_INET, b'1234')\nopen(p, 'rb')\n") == []
