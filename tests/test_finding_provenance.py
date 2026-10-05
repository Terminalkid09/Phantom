"""Evidence provenance / freshness / belief score (brief §7–§8)."""
from phantom.automation.belief import Finding


def test_defaults_keep_positional_construction_compatible():
    # the four original positional args still mean what they meant
    f = Finding("service", "tcp/80", {"port": "80"}, 0.8)
    assert f.kind == "service" and f.confidence == 0.8
    assert f.source_reliability == 0.5
    assert f.evidence_quality == 0.5
    assert f.ttl == 0.0


def test_no_ttl_never_expires():
    f = Finding("service", "tcp/80", {}, ttl=0.0)
    assert f.freshness(now=f.observed_at + 10 ** 9) == 1.0
    assert f.expired(now=f.observed_at + 10 ** 9) is False


def test_freshness_decays_to_zero_at_ttl():
    f = Finding("service", "tcp/80", {}, observed_at=1000.0, ttl=100.0)
    assert f.freshness(now=1000.0) == 1.0
    assert abs(f.freshness(now=1050.0) - 0.5) < 1e-9
    assert f.freshness(now=1100.0) == 0.0
    assert f.expired(now=1100.0) is True


def test_belief_score_multiplies_provenance():
    f = Finding("service", "tcp/80", {}, confidence=1.0,
                source_reliability=0.9, evidence_quality=0.8, ttl=0.0)
    assert abs(f.belief_score() - 0.72) < 1e-9
    # equal confidence, different provenance -> different score
    weak = Finding("service", "tcp/80", {}, confidence=1.0,
                   source_reliability=0.2, evidence_quality=0.2, ttl=0.0)
    assert weak.belief_score() < f.belief_score()


def test_provenance_survives_a_round_trip():
    from phantom.automation.belief import WorldModel
    wm = WorldModel(target="10.0.0.5")
    wm.add_finding("service", "tcp/80", {"port": "80"}, confidence=0.8,
                   source="scan", evidence="80/tcp open")
    wm._findings[("service", "tcp/80")].source_reliability = 0.95
    wm._findings[("service", "tcp/80")].ttl = 3600.0

    restored = WorldModel.from_dict(wm.to_dict())
    f = restored.get("service", "tcp/80")
    assert f.source_reliability == 0.95
    assert f.ttl == 3600.0
