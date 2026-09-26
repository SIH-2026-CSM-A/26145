"""CTU-13 labels joined to dumped flows on endpoints, ports, protocol and time.

The .binetflow files are Argus bidirectional flows labelled by host (scenario READMEs):
From-Botnet = started by an infected host; From-Normal = started by a hand-checked normal host;
To-Botnet / To-Normal = started by unknown hosts toward them ("should not be considered
malicious per se"); everything else Background (unlabelled). Only From-Botnet (1) and
From-Normal (0) are used for supervised training.
"""

import bisect
import csv
from collections import Counter, defaultdict
from datetime import datetime
from typing import Dict, Iterable, List, Optional, Tuple
from zoneinfo import ZoneInfo

TRAIN_LABELS = {"botnet": 1, "normal": 0}
CODES = ("botnet", "normal", "to-botnet", "to-normal", "background")
TOLERANCE_S = 1.0  # Argus and our tracker timestamp the same packets; allow for rounding
PRAGUE = ZoneInfo("Europe/Prague")  # binetflow StartTime is capture-local time

# Scenario -> family and behaviour, from each scenario README ("Probable Name") and the
# CTU-13 paper's scenario table (Garcia et al., Computers & Security 45, 2014).
SCENARIOS = {
    1: "neris-irc-spam-clickfraud", 5: "virut-spam-portscan-http", 6: "donbot-portscan",
    11: "rbot-irc-icmp-ddos", 12: "nsisay-p2p",
}


def label_code(label: str) -> str:
    for prefix, code in (("flow=From-Botnet", "botnet"), ("flow=From-Normal", "normal"),
                         ("flow=To-Botnet", "to-botnet"), ("flow=To-Normal", "to-normal")):
        if label.startswith(prefix):
            return code
    return "background"


def _key(proto: str, a: str, pa: str, b: str, pb: str) -> Tuple:
    """Orientation-free key; ICMP 'ports' are type/id fields in Argus, so ICMP keys on hosts."""
    proto = proto.upper()
    if proto not in ("TCP", "UDP"):
        return (proto,) + tuple(sorted((a, b)))
    return (proto,) + tuple(sorted(((a, _port(pa)), (b, _port(pb)))))


def _port(p) -> int:
    """Argus writes decimal ports; a few rows carry hex (0x...) or nothing."""
    p = str(p).strip()
    try:
        return int(p, 16) if p.startswith("0x") else int(float(p)) if p else -1
    except ValueError:
        return -1


class FlowLabels:
    """Index of one scenario's binetflow rows, queried by flow identity and time."""

    def __init__(self, rows: Iterable[Dict[str, str]]):
        by_key: Dict[Tuple, List] = defaultdict(list)
        self.codes: List[str] = []
        for i, r in enumerate(rows):
            start = datetime.strptime(r["StartTime"], "%Y/%m/%d %H:%M:%S.%f").replace(tzinfo=PRAGUE).timestamp()
            code = label_code(r["Label"])
            self.codes.append(code)
            by_key[_key(r["Proto"], r["SrcAddr"], r["Sport"], r["DstAddr"], r["Dport"])].append(
                (start, start + float(r["Dur"] or 0), i))
        self.index = {}
        for k, lst in by_key.items():
            lst.sort()
            self.index[k] = ([s for s, _, _ in lst], lst, max(e - s for s, e, _ in lst))
        self.matched_rows = set()

    @classmethod
    def from_file(cls, path: str) -> "FlowLabels":
        with open(path, newline="") as fh:
            return cls(csv.DictReader(fh))

    def label(self, proto: str, src: str, sport, dst: str, dport, start: float, last: float) -> str:
        """The one code of every row overlapping [start, last] +- tolerance; 'unmatched' if
        none overlaps, 'ambiguous' if the overlapping rows disagree."""
        entry = self.index.get(_key(proto, src, "" if sport is None else sport, dst, dport))
        if entry is None:
            return "unmatched"
        starts, rows, max_dur = entry
        hi = bisect.bisect_right(starts, last + TOLERANCE_S)
        lo = bisect.bisect_left(starts, start - TOLERANCE_S - max_dur)
        found = set()
        for s, e, i in rows[lo:hi]:
            if e >= start - TOLERANCE_S:
                found.add(self.codes[i])
                self.matched_rows.add(i)
        if not found:
            return "unmatched"
        return found.pop() if len(found) == 1 else "ambiguous"

    def coverage(self, flow_codes: Counter) -> Dict[str, object]:
        """Our flows per assigned code, and the share of labelled rows any flow matched."""
        rows, matched = Counter(self.codes), Counter(self.codes[i] for i in self.matched_rows)
        return {"flows_by_code": dict(flow_codes),
                "binetflow_rows": dict(rows),
                "binetflow_rows_matched": dict(matched),
                "row_match_share": {c: round(matched[c] / rows[c], 4) for c in CODES if rows[c]}}


def train_label(code: str) -> Optional[int]:
    return TRAIN_LABELS.get(code)


# Generated attack captures (utils/attack_scenarios.py), labelled by construction: a flow is
# malicious when it touches the scenario's attack endpoint, else it is that capture's benign
# baseline. DGA, tunnel and TLS-beacon captures are left out: those classes are rule-detected
# (the CTU training captures carry no DNS/TLS content, docs/MODELS.md).
GENERATED = {
    "syn_flood": ("10.50.0.10", "THREAT_DDOS_VOLUME"),
    "udp_reflection": ("10.50.0.20", "THREAT_DDOS_VOLUME"),
    "single_source_flood": ("198.51.100.66", "THREAT_DDOS_VOLUME"),
    "c2_beacon": ("203.0.113.66", "THREAT_C2_BEACON"),
    "port_sweep": ("192.168.1.52", "THREAT_RECON_PORTSCAN"),
    "exfil_upload": ("203.0.113.99", "THREAT_EXFILTRATION"),
}


def generated_label(scenario: str, src: str, dst: str) -> Tuple[int, str]:
    endpoint, threat_class = GENERATED[scenario]
    return (1, threat_class) if endpoint in (src, dst) else (0, "benign-baseline")
