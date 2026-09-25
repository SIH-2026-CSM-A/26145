"""Each detector fires on its own attack capture, replayed through the real pipeline."""

import collections

import pytest

from sih26145.ingest.tls_fingerprint import ja4, parse_hello
from sih26145.orchestrator import ThreatDetectionPipeline
from sih26145.utils import attack_scenarios as atk
from sih26145.utils.benign_scenarios import CLIENT_CIPHERS, CLIENT_EXTS, T0, _web, tls_mail_and_dot
from sih26145.utils.pcap_generator import _write, tls_client_hello


async def alerts_for(tmp_path, packets):
    pcap = str(tmp_path / "capture.pcap")
    _write(pcap, packets)
    pipeline = ThreatDetectionPipeline(":memory:")
    try:
        return await pipeline.process_pcap(pcap)
    finally:
        await pipeline.storage.close()


def by_rule(alerts):
    return collections.Counter((a.threat_class, a.detection["rule_matches"][0]) for a in alerts)


@pytest.mark.asyncio
@pytest.mark.parametrize("scenario,threat_class,rule", [
    ("syn_flood", "THREAT_DDOS_VOLUME", "RULE_DDOS_SYN_FLOOD"),
    ("udp_reflection", "THREAT_DDOS_VOLUME", "RULE_DDOS_UDP_REFLECTION"),
    ("single_source_flood", "THREAT_DDOS_VOLUME", "RULE_DDOS_VOLUME_BASELINE"),
    ("dns_tunnel", "THREAT_DNS_TUNNEL", "RULE_DNS_TUNNEL_VOLUME_LENGTH"),
    ("tls_beacon", "THREAT_ENCRYPTED_ANOMALY", "RULE_TLS_RARE_JA4_REPEATED"),
    ("port_sweep", "THREAT_RECON_PORTSCAN", "RULE_RECON_FANOUT_SYN_ONLY"),
    ("exfil_upload", "THREAT_EXFILTRATION", "RULE_EXFIL_OUTBOUND_RATIO"),
])
async def test_attack_fires_its_detector_exactly_once(tmp_path, scenario, threat_class, rule):
    counts = by_rule(await alerts_for(tmp_path, atk.ATTACK_SCENARIOS[scenario]()))
    assert counts[(threat_class, rule)] == 1, dict(counts)
    # nothing else fires, except C2 on the TLS beacon (it is also periodic)
    others = {k for k in counts if k[0] not in (threat_class, "THREAT_C2_BEACON" if scenario == "tls_beacon" else "")}
    assert others == set(), dict(counts)


@pytest.mark.asyncio
@pytest.mark.parametrize("jitter", [0.2, 0.4])
async def test_c2_fires_at_20_and_40_percent_jitter(tmp_path, jitter):
    alerts = await alerts_for(tmp_path, atk.c2_beacon(jitter=jitter))
    c2 = [a for a in alerts if a.threat_class == "THREAT_C2_BEACON"]
    assert c2, "beacon not detected"
    assert {a.flow["dst_ip"] for a in c2} == {"203.0.113.66"}
    cv = next(e for e in c2[0].evidence if e["feature"] == "pair_iat_cv")["value"]
    assert cv <= 0.35 and cv > jitter / 4  # jitter is really there


@pytest.mark.asyncio
async def test_allowlisted_poller_source_is_not_a_beacon(tmp_path, monkeypatch):
    allow = tmp_path / "pollers.txt"
    allow.write_text("# backup agent\n192.168.1.70/32\n")
    monkeypatch.setenv("SIH26145_POLLER_ALLOWLIST", str(allow))
    alerts = await alerts_for(tmp_path, atk.c2_beacon())
    assert [a for a in alerts if a.threat_class == "THREAT_C2_BEACON"] == []


@pytest.mark.asyncio
async def test_known_bad_ja4_list_fires_on_listed_fingerprint(tmp_path, monkeypatch):
    listed = ja4(parse_hello(tls_client_hello("imap.example.net", CLIENT_CIPHERS, CLIENT_EXTS)))
    bad = tmp_path / "ja4_bad.txt"
    bad.write_text(f"{listed}  # test entry\n")
    monkeypatch.setenv("SIH26145_JA4_KNOWN_BAD", str(bad))
    counts = by_rule(await alerts_for(tmp_path, tls_mail_and_dot()))
    assert counts == {("THREAT_ENCRYPTED_ANOMALY", "RULE_TLS_KNOWN_BAD_JA4"): 1}  # IMAPS+SMTPS share one pair


@pytest.mark.asyncio
async def test_dga_with_resolver_answers_uses_nxdomain(tmp_path):
    (alert,) = [a for a in await alerts_for(tmp_path, atk.dga_lookups()) if a.threat_class == "THREAT_DNS_DGA"]
    assert alert.severity == "HIGH" and alert.substitutions == []
    assert {"src_nxdomain_rate_w", "src_high_entropy_qnames_w"} <= {e["feature"] for e in alert.evidence}


@pytest.mark.asyncio
async def test_dga_without_answers_names_the_substitution(tmp_path):
    alerts = await alerts_for(tmp_path, atk.dga_lookups(with_responses=False))
    (alert,) = [a for a in alerts if a.threat_class == "THREAT_DNS_DGA"]
    assert alert.severity == "MEDIUM"
    assert alert.substitutions[0]["unavailable_on_this_flow"] == "src_nxdomain_rate_w"
    assert "src_nxdomain_rate_w" not in {e["feature"] for e in alert.evidence}


@pytest.mark.asyncio
@pytest.mark.parametrize("shared", [False, True])
async def test_recon_skips_shared_infrastructure(tmp_path, shared):
    target = "10.0.0.80"
    packets = atk.port_sweep(T0 + 40, target=target)
    if shared:  # 30 hosts already use the target: it is a shared server, not a scan victim
        packets += sum((_web(T0 + i, f"10.60.0.{i + 1}", target, 47000 + i) for i in range(30)), [])
    recon = [a for a in await alerts_for(tmp_path, packets) if a.threat_class == "THREAT_RECON_PORTSCAN"]
    assert len(recon) == (0 if shared else 1)


def test_ramnit_dga_reproduces_published_domains():
    # github.com/baderj/domain_generation_algorithms, ramnit/example_domains.txt
    assert atk.ramnit_dga(0x79159C10, 5) == [
        "knpqxlxcwtlvgrdyhd.com", "nvlyffua.com", "hgyudheedieibxy.com", "anrylixwcbnjopdd.com", "vrndmdrdrjoff.com"]
