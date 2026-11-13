"""Evidence-aware belief merge (AutoModeBrief §8–§9).

Pins the corroboration bonus, the count of independent sources folded into a
stored belief, and the deterministic merge that keeps contradicting evidence
instead of letting scheduling order decide the truth.
"""
from phantom.automation.belief import Finding, WorldModel, merge_findings


def _f(value, source="scan", conf=0.8, rel=0.9, qual=0.9, indep=0):
    return Finding("service", "tcp/443", value, confidence=conf, source=source,
                   source_reliability=rel, evidence_quality=qual,
                   independent_sources=indep, ttl=0.0)


def test_no_corroboration_is_neutral():
    f = _f({"v": 1})
    assert f.independence_bonus() == 1.0
    f2 = _f({"v": 1}, indep=1)
    assert f2.independence_bonus() == 1.0     # a single source: neutral


def test_corroboration_bonus_is_bounded():
    assert abs(_f({"v": 1}, indep=2).independence_bonus() - 1.1) < 1e-9
    assert abs(_f({"v": 1}, indep=3).independence_bonus() - 1.2) < 1e-9
    assert _f({"v": 1}, indep=99).independence_bonus() == 1.3   # capped


def test_add_finding_counts_independent_sources():
    wm = WorldModel(target="10.0.0.5")
    wm.add_finding("service", "tcp/80", {"port": "80"}, confidence=0.8,
                   source="nmap")
    assert wm.get("service", "tcp/80").independent_sources == 1  # one source
    wm.add_finding("service", "tcp/80", {"port": "80"}, confidence=0.7,
                   source="http_probe")
    f = wm.get("service", "tcp/80")
    assert f.independent_sources == 2          # two distinct sources
    assert f.confidence == 0.8                 # weaker restatement kept max
    # a repeat from the SAME source does not inflate the count
    wm.add_finding("service", "tcp/80", {"port": "80"}, confidence=0.6,
                   source="nmap")
    assert wm.get("service", "tcp/80").independent_sources == 2


def test_merge_picks_best_by_evidence_not_order():
    weak = _f({"banner": "nginx"}, source="shodan", conf=0.5, rel=0.6, qual=0.5)
    strong = _f({"banner": "nginx"}, source="http_probe", conf=0.95,
                rel=0.95, qual=0.95)
    # regardless of order, the stronger evidence wins
    for order in ([weak, strong], [strong, weak]):
        res = merge_findings("service", "tcp/443", order)
        assert res.current is strong
        assert res.current.source == "http_probe"


def test_merge_retains_contradicting_evidence():
    a = _f({"version": "1.24"}, source="http_probe", conf=0.9)
    b = _f({"version": "1.18"}, source="shodan", conf=0.5, rel=0.6, qual=0.5)
    res = merge_findings("service", "tcp/443", [a, b])
    assert res.current.value == {"version": "1.24"}
    assert len(res.rejected) == 1
    assert res.rejected[0].value == {"version": "1.18"}
    assert "contradicting" in res.reason


def test_merge_counts_corroborating_sources():
    a = _f({"v": 1}, source="scan1", conf=0.8)
    b = _f({"v": 1}, source="scan2", conf=0.7)
    c = _f({"v": 1}, source="scan1", conf=0.6)     # same source: a repeat
    res = merge_findings("service", "tcp/443", [a, b, c])
    assert res.independent_sources == 2            # scan1 + scan2
    assert len(res.corroborating) == 1             # b
    assert len(res.alternatives) == 1              # c (repeat)


def test_merge_is_empty_safe():
    res = merge_findings("service", "tcp/443", [])
    assert res.current is None
    assert res.reason
