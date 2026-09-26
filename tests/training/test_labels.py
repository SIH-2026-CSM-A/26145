"""CTU-13 label join: host-labelled Argus rows matched to our flows by identity and time."""

import csv
import io
from datetime import datetime, timezone

from sih26145.training.labels import FlowLabels, generated_label, label_code, train_label

HEAD = "StartTime,Dur,Proto,SrcAddr,Sport,Dir,DstAddr,Dport,State,sTos,dTos,TotPkts,TotBytes,SrcBytes,Label"
ROWS = [
    "2011/08/15 16:52:50.947767,2.0,udp,147.32.84.165,1025,  <->,147.32.80.9,53,CON,0,0,2,203,64,flow=From-Botnet-V46-UDP-DNS",
    "2011/08/15 16:53:00.000000,5.0,tcp,147.32.84.170,40000,   ->,1.2.3.4,443,SA,0,0,9,900,300,flow=From-Normal-V46-HTTPS",
    "2011/08/15 16:53:01.000000,1.0,tcp,147.32.84.170,40000,   ->,1.2.3.4,443,SA,0,0,1,60,60,flow=Background",
    "2011/08/15 16:54:00.000000,0.0,icmp,5.6.7.8,0x0008,   ->,147.32.84.165,0x2311,ECO,0,0,1,98,98,flow=To-Botnet-V46-ICMP",
]


def labels():
    return FlowLabels(csv.DictReader(io.StringIO("\n".join([HEAD] + ROWS))))


def epoch(s):  # the rows are Prague summer time, UTC+2
    return datetime.strptime(s, "%Y/%m/%d %H:%M:%S.%f").replace(tzinfo=timezone.utc).timestamp() - 7200


def test_join_uses_prague_time_either_orientation_and_ignores_icmp_ports():
    fl = labels()
    t = epoch("2011/08/15 16:52:51.000000")
    # our flow key was oriented by the resolver's answer: reversed endpoints still match
    assert fl.label("UDP", "147.32.80.9", "53", "147.32.84.165", "1025", t, t + 0.1) == "botnet"
    assert fl.label("UDP", "147.32.80.9", "53", "147.32.84.165", "1025", t + 3600, t + 3600) == "unmatched"
    ti = epoch("2011/08/15 16:54:00.000000")
    assert fl.label("ICMP", "5.6.7.8", "0", "147.32.84.165", "8", ti, ti) == "to-botnet"


def test_disagreeing_rows_are_ambiguous_and_coverage_counts_matches():
    fl = labels()
    t = epoch("2011/08/15 16:53:01.500000")
    assert fl.label("TCP", "147.32.84.170", "40000", "1.2.3.4", "443", t, t) == "ambiguous"
    cov = fl.coverage({"ambiguous": 1})
    assert cov["binetflow_rows"]["normal"] == 1 and cov["binetflow_rows_matched"]["normal"] == 1


def test_only_from_botnet_and_from_normal_train():
    assert [train_label(label_code(r.rsplit(",", 1)[1])) for r in ROWS] == [1, 0, None, None]
    assert generated_label("port_sweep", "192.168.1.52", "10.0.0.200") == (1, "THREAT_RECON_PORTSCAN")
    assert generated_label("single_source_flood", "10.40.1.1", "10.30.0.90") == (0, "benign-baseline")
