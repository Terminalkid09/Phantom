"""The nonlinear ranker: same contract, same gate, and it refuses to lie.

Three properties, each of which is a bug if it breaks:

1. the runtime forward pass (plain Python, shipped) and the trainer's
   (numpy, not shipped) produce the same score for the same weights. A drift
   there is invisible at training time and wrong in the field;
2. the trainer REFUSES to promote a model fitted on fewer rows than its own
   parameter count supports. 34 rows and a few hundred weights is
   memorisation; a higher number from it would be a worse result dressed up
   as a better one;
3. the hidden layer earns its keep: a label that depends on an AND of two
   context flags is not expressible by the linear ranker's per-feature
   weights, and is expressible here. If that ever stops being true, the model
   can go and the linear one should.
"""

import json
import math

import pytest

from phantom.automation.ai import net as runtime_net
from training import net as training_net
from training.ranker import train as train_linear


def _payload(web: bool, deliver: bool) -> dict:
    return {
        "candidates": [{"id": "a"}, {"id": "b"}],
        "services": ([{"service": "http"}] if web else [{"service": "ssh"}]),
        "goal": "deliver" if deliver else "foothold",
        "profile": "balanced",
        "cves": [],
        "already_tried": [],
    }


def _toy_rows(count: int = 60):
    """Labels that are an XOR: a first only when exactly ONE flag is set.

    Two false starts are recorded here because each one made the test prove
    nothing:

    * ``web = i % 2``, ``deliver = i % 4`` made ``deliver`` imply ``web``, so
      one flag predicted everything (both models scored 1.0);
    * an AND label is still AFFINE — ``web + deliver > 1.5`` separates it — so
      the linear ranker solved it too (both 1.0 again).

    XOR is the smallest ordering no affine function can produce: it needs
    (alone → b), (the other alone → b), (both → a) and (neither → a) at once.
    All four cells are present, in equal number, in the training slice and in
    the holdout.
    """
    combinations = ((False, False), (False, True), (True, False), (True, True))
    rows = []
    for index in range(count):
        web, deliver = combinations[index % len(combinations)]
        rows.append({
            "id": f"r{index}",
            "input": _payload(web, deliver),
            "expected": {"ranking": ["a", "b"] if (web != deliver)
                         else ["b", "a"]},
        })
    return rows


def _ndcg(ranker, rows) -> float:
    from training.eval import score_one

    return sum(score_one("ndcg", row["expected"],
                         {"ranking": ranker.rank(row["input"])})
               for row in rows) / len(rows)


class TestTheRuntimeAgreesWithTheTrainer:
    """Two implementations of one forward pass, compared numerically."""

    def test_the_exported_weights_score_identically(self):
        fitted = training_net.train(_toy_rows(40), epochs=60)
        exported = training_net.NetRanker.from_dict(
            json.loads(json.dumps(fitted.to_dict())))
        runtime = runtime_net.NetRanker.from_dict(fitted.to_dict())

        payload = _payload(web=True, deliver=True)
        for cid in ("a", "b"):
            trainer_score = exported.score(payload, cid)
            runtime_score = runtime.score(
                cid, {key: value for key, value in
                      zip(training_net.CONTEXT,
                          training_net._context(payload, cid))})
            assert runtime_score == pytest.approx(trainer_score, abs=1e-6)

    def test_the_runtime_ranks_per_candidate_context(self):
        # `contexts` overrides the shared context per id, exactly as the
        # linear ranker's contract says: `is_cve` is a property of one move.
        fitted = training_net.train(_toy_rows(40), epochs=60)
        runtime = runtime_net.NetRanker.from_dict(fitted.to_dict())
        order = runtime.rank(["a", "b"], context={"web_surface": 1.0},
                             contexts={"a": {"is_cve": 1.0}})
        assert sorted(order) == ["a", "b"]

    def test_an_unknown_candidate_is_still_scored(self):
        fitted = training_net.train(_toy_rows(40), epochs=60)
        runtime = runtime_net.NetRanker.from_dict(fitted.to_dict())
        value = runtime.score("never-seen", {"web_surface": 1.0})
        assert isinstance(value, float) and math.isfinite(value)


class TestItRefusesToMemorise:
    """The floor is the point: below it, a better score is a worse result."""

    def test_the_real_corpus_is_below_the_floor(self):
        train_rows, test_rows = training_net.rows_for("exploit")
        if not train_rows or not test_rows:
            pytest.skip("corpus not built in this checkout")
        ids = {cid for row in train_rows
               for cid in training_net._candidates(row.get("input") or {})}
        params = training_net.n_params(len(ids))
        total = len(train_rows) + len(test_rows)
        assert total < max(training_net.MIN_ROWS,
                          int(training_net.MIN_ROWS_PER_PARAM * params)), (
            "the corpus grew past the floor: the refusal test needs to be "
            "replaced by a real promotion test")

    def test_it_exits_nonzero_and_writes_no_manifest(self, tmp_path, capsys):
        out = tmp_path / "net.json"
        manifest = tmp_path / "manifest.json"
        code = training_net.main(["--out", str(out),
                                  "--write-manifest", str(manifest)])
        printed = capsys.readouterr().out
        if "no rows" in printed:
            pytest.skip("corpus not built in this checkout")
        assert code == 1
        assert "REFUSING TO TRAIN" in printed
        assert not manifest.exists(), "a refusal must not promote anything"

    def test_force_trains_but_never_promotes(self, tmp_path, capsys):
        out = tmp_path / "net.json"
        manifest = tmp_path / "manifest.json"
        training_net.main(["--force", "--epochs", "5", "--out", str(out),
                           "--write-manifest", str(manifest)])
        printed = capsys.readouterr().out
        if "no rows" in printed:
            pytest.skip("corpus not built in this checkout")
        assert out.exists(), "--force should still write the artefact"
        assert not manifest.exists(), "--force is inspection, not promotion"


class TestTheHiddenLayerEarnsItsKeep:
    """An XOR ordering: the linear form cannot produce it, this one can.

    Capacity and epochs are explicit here, and they were MEASURED before being
    written down: with the module defaults (8 hidden, 300 epochs) the net
    stalls at the same 0.9299 the linear ranker reaches, and with 16 hidden /
    2000 epochs / 0.05 it reaches 1.0000 on the holdout. A test that asserted
    the claim without that measurement would be asserting a belief.
    """

    def test_the_net_learns_an_order_the_linear_model_cannot(self):
        rows = _toy_rows(60)
        fit, holdout = rows[:48], rows[48:]

        nonlinear = _ndcg(training_net.train(fit, hidden=16, epochs=2000,
                                            rate=0.05), holdout)
        linear = _ndcg(train_linear(fit), holdout)

        assert nonlinear > linear, (nonlinear, linear)
        assert nonlinear == pytest.approx(1.0, abs=0.02)


class TestPromotionIsTheManifest:
    """A net on disk is a candidate; only a manifest makes it a model."""

    def test_no_manifest_means_not_promoted(self, tmp_path, monkeypatch):
        monkeypatch.setattr(runtime_net, "MODELS_DIR", tmp_path)
        (tmp_path / "exploit").mkdir()
        (tmp_path / "exploit" / "net.json").write_text("{}", encoding="utf-8")
        assert runtime_net.promoted("exploit") is None

    def test_a_promoted_mlp_manifest_loads_the_net(self, tmp_path, monkeypatch):
        monkeypatch.setattr(runtime_net, "MODELS_DIR", tmp_path)
        root = tmp_path / "exploit"
        root.mkdir()
        fitted = training_net.train(_toy_rows(40), epochs=20)
        (root / "net.json").write_text(json.dumps(fitted.to_dict()),
                                      encoding="utf-8")
        (root / "manifest.json").write_text(json.dumps(
            {"promoted": True, "kind": "mlp", "net": "net.json"}),
            encoding="utf-8")
        loaded = runtime_net.promoted("exploit")
        assert loaded is not None and loaded.ids == fitted.ids

    def test_a_linear_manifest_is_not_a_net(self, tmp_path, monkeypatch):
        monkeypatch.setattr(runtime_net, "MODELS_DIR", tmp_path)
        root = tmp_path / "exploit"
        root.mkdir()
        (root / "manifest.json").write_text(json.dumps(
            {"promoted": True, "kind": "linear-ranker",
             "ranker": "ranker.json"}), encoding="utf-8")
        assert runtime_net.promoted("exploit") is None
