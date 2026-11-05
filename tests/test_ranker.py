"""The CPU ranker is the one ML component measured without a GPU.

These tests pin three things: training is deterministic, the score is used the
same way in training and at runtime, and the runtime refuses a ranker whose
manifest did not pass the gate (a JSON file in ``models/`` is not a promotion).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from types import SimpleNamespace

from phantom.automation.ai import linear
from training import ranker as training_ranker


def _row(ranking, candidates, *, tried=(), goal="foothold", web=True):
    services = [{"port": "8080", "service": "http"}] if web else []
    return {"phase": "exploit",
            "input": {"candidates": [{"id": c} for c in candidates],
                      "already_tried": list(tried),
                      "services": services, "goal": goal,
                      "mode": "balanced", "profile": "default"},
            "expected": {"ranking": list(ranking)}}


def test_training_is_deterministic_and_learns_the_order():
    rows = [_row(["web_rce", "scan_tcp", "web_creds"],
                 ["scan_tcp", "web_rce", "web_creds"]),
            _row(["web_rce", "web_creds", "scan_tcp"],
                 ["scan_tcp", "web_creds", "web_rce"]),
            _row(["beacon_deploy", "scan_tcp"], ["scan_tcp", "beacon_deploy"])]
    first = training_ranker.train(rows, epochs=50)
    second = training_ranker.train(rows, epochs=50)
    assert first.to_dict() == second.to_dict()
    assert first.rank(rows[0]["input"])[0] == "web_rce"


def test_the_exported_weights_reproduce_the_training_score(tmp_path):
    rows = [_row(["web_rce", "scan_tcp"], ["scan_tcp", "web_rce"])]
    trained = training_ranker.train(rows, epochs=20)
    path = tmp_path / "ranker.json"
    path.write_text(json.dumps(trained.to_dict()), encoding="utf-8")
    loaded = linear.load(path)
    assert loaded is not None
    payload = rows[0]["input"]
    context = linear.context_from_candidates(
        [type("C", (), {"port": "8080"})()], mode="balanced")
    assert (loaded.rank([c["id"] for c in payload["candidates"]], context)
            == trained.rank(payload))


def test_is_cve_is_per_candidate_at_runtime():
    """`is_cve` is a property of ONE move, and the runtime used to lose it.

    `context_from_candidates` returned ONE shared dict with ``is_cve`` pinned
    at 0.0, so every ``interactions[cid]["is_cve"]`` the trainer fitted was
    multiplied by zero: the exported model was not the model that had been
    measured. `contexts_for_candidates` fills the flag per id.
    """
    model = linear.LinearRanker(
        weights={"a": 0.0, "b": 0.0},
        context={key: 0.0 for key in linear.CONTEXT},
        interactions={"a": {"is_cve": 2.0}, "b": {"is_cve": 0.0}},
        bias=0.0, version="t")
    cands = [SimpleNamespace(id="a", cve="CVE-2021-41773", port="80"),
             SimpleNamespace(id="b", cve="", port="80")]
    contexts = linear.contexts_for_candidates(cands, mode="balanced")
    assert contexts["a"]["is_cve"] == 1.0
    assert contexts["b"]["is_cve"] == 0.0
    assert model.rank(["b", "a"], contexts=contexts)[0] == "a"
    # the shared dict alone cannot express it — that was the old behaviour
    shared = linear.context_from_candidates(cands, mode="balanced")
    assert model.rank(["b", "a"], shared)[0] == "b"


def _payload(candidates, *, services=None, goal="foothold", profile="default",
             cves=None, tried=()):
    return {"candidates": [dict(c) for c in candidates],
            "services": services or [],
            "goal": goal, "profile": profile, "mode": "balanced",
            "cves": list(cves or []), "already_tried": list(tried)}


def test_the_candidate_priority_is_a_feature_the_model_can_use():
    """Priority is IN the corpus and was invisible to the model.

    Every ordered pair appears in both directions with the priority flipped,
    so the per-id weights cancel exactly and only a context term can explain
    the labels: if this passes, the feature is really being used.
    """
    ids = ["alpha", "beta", "gamma", "delta"]
    rows = []
    for better in ids:
        for worse in ids:
            if better == worse:
                continue
            rows.append({"phase": "exploit",
                         "input": _payload([{"id": better, "priority": 1.0},
                                            {"id": worse, "priority": 0.0}]),
                         "expected": {"ranking": [better, worse]}})
    model = training_ranker.train(rows, epochs=300)
    fresh = _payload([{"id": "alpha"}, {"id": "beta", "priority": 0.9}])
    assert model.rank(fresh)[0] == "beta"


def test_a_table_that_carries_a_cve_is_flagged_as_such():
    rows = [{"phase": "exploit",
             "input": _payload([{"id": "web_rce"}, {"id": "scan_tcp"}],
                               cves=["CVE-2021-41773"]),
             "expected": {"ranking": ["web_rce", "scan_tcp"]}},
            {"phase": "exploit",
             "input": _payload([{"id": "web_rce"}, {"id": "scan_tcp"}]),
             "expected": {"ranking": ["scan_tcp", "web_rce"]}}]
    model = training_ranker.train(rows, epochs=200)
    assert model.score(_payload([{"id": "web_rce"}], cves=["CVE-1"]),
                       "web_rce") > model.score(_payload([{"id": "web_rce"}]),
                                                "web_rce")


def test_the_export_round_trips_and_scores_identically():
    rows = [_row(["web_rce", "scan_tcp"], ["scan_tcp", "web_rce"]),
            _row(["beacon_deploy", "scan_tcp"], ["scan_tcp", "beacon_deploy"],
                 goal="deliver")]
    trained = training_ranker.train(rows, epochs=40)
    restored = training_ranker.Ranker.from_dict(trained.to_dict())
    payload = rows[1]["input"]
    ids = [c["id"] for c in payload["candidates"]]
    assert [restored.score(payload, cid) for cid in ids] == \
        [trained.score(payload, cid) for cid in ids]
    assert restored.rank(payload) == trained.rank(payload)


def test_an_old_artefact_with_five_context_keys_still_loads_and_scores():
    """A ranker trained before the two new features must not become unusable.

    The exported shape is additive: the new keys default to 0.0, so an old
    artefact scores exactly what it scored when it was measured.
    """
    old = {"phase": "exploit", "version": "ranker-old",
           "weights": {"a": 0.0, "b": 0.0},
           "context": {"tried": 0.0, "is_cve": 0.0, "web_surface": 0.0,
                       "goal_deliver": 0.0, "profile_stealth": 0.0},
           "interactions": {"a": {"is_cve": 0.0, "web_surface": 0.5},
                            "b": {"is_cve": 0.0}},
           "bias": 0.0}
    model = training_ranker.Ranker.from_dict(old)
    payload = _payload([{"id": "a"}, {"id": "b"}],
                       services=[{"port": "443", "service": "https"}])
    assert model.score(payload, "a") == pytest.approx(0.5)
    assert model.rank(payload) == ["a", "b"]
    # the runtime mirror reads the same artefact shape
    runtime = linear.LinearRanker.from_dict(old)
    assert runtime.rank(["a", "b"], {"web_surface": 1.0}) == ["a", "b"]


def test_the_runtime_mirror_computes_the_same_vector_as_training():
    """The weights are keyed by NAME: a drift is a silently wrong score."""
    assert linear.CONTEXT == training_ranker.CONTEXT
    payloads = [
        _payload([{"id": "web_rce", "priority": 0.8}, {"id": "scan_tcp"}],
                 services=[{"port": "8080", "service": "http"}],
                 goal="deliver", profile="stealth"),
        _payload([{"id": "CVE-2021-41773"}, {"id": "ssh_brute"}],
                 services=[{"port": "22", "service": "ssh"}],
                 cves=["CVE-2021-41773"], tried=["ssh_brute"]),
        _payload([{"id": "beacon_deploy"}], profile="enterprise"),
    ]
    for payload in payloads:
        web_port = next((str(s.get("port")) for s in payload["services"]
                         if str(s.get("service")) in ("http", "https", "ssl")),
                        "22")
        cands = []
        for row in payload["candidates"]:
            cid = str(row["id"])
            cands.append(SimpleNamespace(
                id=cid,
                cve=cid if cid.upper().startswith("CVE-") else "",
                port=web_port,
                priority=row.get("priority", 0.0)))
        runtime = linear.contexts_for_candidates(
            cands, goal=payload["goal"], profile=payload["profile"],
            tried=payload["already_tried"])
        for cid in runtime:
            expected = dict(zip(training_ranker.CONTEXT,
                                training_ranker._context(payload, cid)))
            assert runtime[cid] == pytest.approx(expected), cid


def test_the_runtime_refuses_a_manifest_without_a_passed_gate(tmp_path):
    root = tmp_path / "project"
    folder = root / "models" / "exploit" / "v1"
    folder.mkdir(parents=True)
    (folder / "ranker.json").write_text(json.dumps(
        {"weights": {"a": 1.0}, "context": {}, "bias": 0.0}), encoding="utf-8")
    manifest = {"phase": "exploit", "version": "v1",
                "base_model": "linear-pairwise-ranker", "sha256": "0" * 64,
                "trained_at": "2026-10-29T00:00:00Z",
                "eval": {"ndcg": 0.9}, "baseline": {"ndcg": 0.8},
                "kind": "linear-ranker", "ranker": "ranker.json",
                "promoted": True,
                "eval_gate": {"verdict": "reject", "n": 40, "delta": -0.1}}
    (folder / "manifest.json").write_text(json.dumps(manifest),
                                          encoding="utf-8")
    assert linear.promoted("exploit", models_dir=root / "models") is None

    manifest["eval_gate"] = {"verdict": "promote", "n": 40, "delta": 0.03,
                             "ci_low": 0.01, "min_rows": 20}
    (folder / "manifest.json").write_text(json.dumps(manifest),
                                          encoding="utf-8")
    loaded = linear.promoted("exploit", models_dir=root / "models")
    assert loaded is not None and loaded.rank(["a", "b"], {})[0] == "a"


def _promote_verdict(*args, **kwargs):
    """A neutral `promote` gate, so these tests measure PROVENANCE, not luck."""
    return {"verdict": "promote", "delta": 0.2, "ci_low": 0.15,
            "ci_high": 0.25, "n": 40, "score": 1.0, "baseline": 0.8,
            "reasons": [], "decide_delta": 0.06}


def test_the_manifest_records_which_baseline_was_measured(tmp_path, monkeypatch):
    """A promotion must say WHAT it beat, not only by how much.

    The shipped ranker was promoted against the training heuristic while the
    reader assumed the production scorer, and the two numbers differ (0.9950
    vs 0.9972 measured 2026-11-05). A manifest that carries only a score
    cannot be audited; `baseline.kind` makes the comparison explicit.
    """
    rows = []
    for _ in range(3):
        row = _row(["web_rce", "scan_tcp"], ["scan_tcp", "web_rce"])
        row["deterministic_rank"] = ["scan_tcp", "web_rce"]
        rows.append(row)
    monkeypatch.setattr(training_ranker, "rows_for",
                        lambda *a, **k: (list(rows), list(rows)))
    monkeypatch.setattr("training.gate.decide", _promote_verdict)

    manifest = tmp_path / "manifest.json"
    code = training_ranker.main([
        "--baseline", "production",
        "--out", str(tmp_path / "ranker.json"),
        "--write-manifest", str(manifest)])
    assert code == 0
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    assert payload["baseline"]["kind"] == "production"
    assert payload["baseline"]["score"] == payload["baseline"]["ndcg"]
    assert "production" in payload["baseline"]["note"]


def test_the_default_baseline_is_the_training_heuristic(tmp_path, monkeypatch):
    """The default path is unchanged — and says out loud what it compared."""
    rows = [_row(["web_rce", "scan_tcp"], ["scan_tcp", "web_rce"])
            for _ in range(3)]
    monkeypatch.setattr(training_ranker, "rows_for",
                        lambda *a, **k: (list(rows), list(rows)))
    monkeypatch.setattr("training.gate.decide", _promote_verdict)

    manifest = tmp_path / "manifest.json"
    code = training_ranker.main([
        "--out", str(tmp_path / "ranker.json"),
        "--write-manifest", str(manifest)])
    assert code == 0
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    assert payload["baseline"]["kind"] == "training"
    assert "NOT the production scorer" in payload["baseline"]["note"]


def test_production_baseline_refuses_a_corpus_without_the_ordering(
        tmp_path, monkeypatch, capsys):
    """Never fall back silently: the run is refused, nothing is written."""
    rows = [_row(["web_rce", "scan_tcp"], ["scan_tcp", "web_rce"])]
    monkeypatch.setattr(training_ranker, "rows_for",
                        lambda *a, **k: (list(rows), list(rows)))

    out = tmp_path / "ranker.json"
    code = training_ranker.main(["--baseline", "production", "--out", str(out)])
    assert code == 4
    err = capsys.readouterr().err
    assert "REFUSED" in err
    assert "nothing was trained or written" in err
    assert not out.exists()


def test_deterministic_ranking_reads_the_corpus_not_the_model():
    row = {"expected": {"ranking": ["a", "b"],
                        "deterministic_rank": ["b", "a"]}}
    assert training_ranker.deterministic_ranking(row) == {
        "ranking": ["b", "a"]}
    assert training_ranker.deterministic_ranking(
        {"expected": {"ranking": ["a", "b"]}}) is None


def test_evaluate_refuses_a_row_without_a_production_ordering():
    rows = [_row(["web_rce", "scan_tcp"], ["scan_tcp", "web_rce"])]
    ranker = training_ranker.train(rows, epochs=5)
    with pytest.raises(ValueError):
        training_ranker.evaluate(ranker, rows, baseline="production")


def test_the_installed_ranker_is_measurable_end_to_end():
    """The shipped artefact must be a promoted, gate-passed score.

    This is a regression contract: if the ranker is retrained and the gate
    rejects it, the runtime must lose its second opinion — not keep an
    unmeasured one.
    """
    loaded = linear.promoted("exploit")
    if loaded is None:
        pytest.skip("no promoted ranker installed in this checkout")
    assert loaded.weights
    assert loaded.rank(["web_rce", "scan_tcp"], {"web_surface": 1.0})


def test_the_installed_ranker_speaks_the_runtime_vocabulary():
    """Every non-zero per-id weight must be an id the runtime can emit.

    This is the defect the scoreboard used to call "efficacia 3/10": the
    promoted model carried ``scan_tcp``/``beacon_deploy``, production emits
    ``noncve:service:ssh:22`` and ``CVE-...``, so every candidate scored the
    bias and the reranker changed nothing. A regression here is silent — the
    model still loads, still answers, and has no effect — so it is pinned.
    """
    loaded = linear.promoted("exploit")
    if loaded is None:
        pytest.skip("no promoted ranker installed in this checkout")
    train_rows, test_rows = training_ranker.rows_for("exploit",
                                                    corpus="production")
    # BOTH halves: the weights are fitted on the train rows, so judging them
    # against the holdout alone reports an id as unscoreable that the trainer
    # legitimately saw.
    everything = list(train_rows) + list(test_rows)
    offenders = training_ranker.unscoreable_weight_ids(loaded, everything)
    assert not offenders, (
        "non-zero weights name ids the production corpus never offered: "
        f"{offenders[:8]}")


def test_the_promoted_ranker_corrects_a_production_ordering():
    """End-to-end: through the production ``rerank`` API, not a bare score.

    The row is one where the deterministic planner (``score_for``) puts an
    already-open FTP service above a reachable RCE; the labelled order puts
    the RCE first. The assertion is on the ORDER the advisor returns, so a
    ranker that is loaded but never applied fails here.
    """
    from phantom.automation.ai.advisors import exploit as advisor
    from phantom.automation.exploit.access import AccessCandidate

    if linear.promoted("exploit") is None:
        pytest.skip("no promoted ranker installed in this checkout")
    path = training_ranker.corpus_paths("exploit", "production")[0]
    rows = [json.loads(line) for line in
            path.read_text(encoding="utf-8").splitlines() if line.strip()]
    row = next((r for r in rows
                if r.get("id") == "prod-ssh-http-apache-ftp"), None)
    if row is None:
        pytest.skip("the production corpus no longer carries that row")

    # The numbers production puts on a candidate of each access class
    # (``access._RANK_SUCCESS`` for a `good` module, and the constant
    # complexity/noise per class). Using ONE fallback for every non-exec row
    # would flatten a file-read service into an `info` lead and hide exactly
    # the ordering this test is about.
    stats = {"exec": (0.75, 0.45, 0.70), "file_read": (0.70, 0.30, 0.40),
             "info": (0.25, 0.55, 0.25)}
    candidates = []
    for cand in row["input"]["candidates"]:
        access = str(cand.get("access") or "info")
        success, complexity, noise = stats.get(access, stats["info"])
        candidates.append(AccessCandidate(
            id=str(cand["id"]), cve=str(cand.get("cve") or ""),
            port=str(cand.get("port") or ""),
            service=str(cand.get("service") or ""),
            product=str(cand.get("product") or ""),
            version=str(cand.get("version") or ""),
            kind=str(cand.get("kind") or ""), access=access,
            success=success, complexity=complexity, noise=noise,
            actionable=True, auto_execute=True, exact_match=True))

    deterministic = [c.id for c in sorted(
        candidates,
        key=lambda c: (-c.score_for("balanced"), -c.access_level,
                       c.complexity, c.noise, c.id))]
    result = advisor.rerank(candidates, "balanced",
                            goal=str(row["input"].get("goal") or ""),
                            profile=str(row["input"].get("profile") or ""))
    expected = list(row["expected"]["ranking"])
    assert [c.id for c in result.ordered] == expected
    assert deterministic != expected
    assert result.applied
