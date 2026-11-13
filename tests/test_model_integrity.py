"""The manifest's sha256 must be TRUE, not decorative.

Measured 2026-11-06: the promoted `ranker-2026-11-03` manifest declared
`ba9023a2…`, the installed file hashed `b7e3b978…`, and `ModelRegistry`
reported `registry_errors = []`. Nothing ever computed the digest, so a ranker
edited after evaluation kept being served as the promoted model — the manifest
was a claim about a file, not a proof of one.

Two defects, both closed here:

* the registry now REPRODUCES the digest (single file, or a directory of
  adapter weights) and refuses a mismatch;
* the digest is computed over the installed bytes, so those bytes have to be
  host-independent. `.gitattributes` marks `models/**` as binary and the
  trainers write with `newline="\\n"`; before that, a Windows checkout held
  CRLF (6002 bytes) where git stored LF (5799), and the "tamper" was really a
  line-ending.
"""
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from phantom.automation.ai import linear, registry

RANKER = {"weights": {"a": 1.0, "b": -1.0},
          "context": {"tried": 0.5}, "interactions": {},
          "bias": 0.0}


def _ranker_json() -> str:
    return json.dumps(RANKER, indent=2, sort_keys=True) + "\n"


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _manifest(**over) -> dict:
    data = {
        "phase": "exploit", "version": "v1",
        "base_model": "linear-pairwise-ranker", "kind": "linear-ranker",
        "ranker": "ranker.json", "sha256": "0" * 64,
        "trained_at": "2026-11-06T00:00:00Z",
        "eval": {"ndcg": 0.95}, "baseline": {"ndcg": 0.80},
        "eval_gate": {"verdict": "promote", "delta": 0.05,
                      "ci_low": 0.02, "n": 40, "min_rows": 20},
        "promoted": True,
    }
    data.update(over)
    return data


def _project(tmp: Path, manifest: dict) -> Path:
    folder = tmp / "models" / "exploit" / "v1"
    folder.mkdir(parents=True)
    ranker = folder / "ranker.json"
    ranker.write_text(_ranker_json(), encoding="utf-8", newline="\n")
    manifest["sha256"] = _sha(ranker)
    (folder / "manifest.json").write_text(json.dumps(manifest, indent=2),
                                          encoding="utf-8", newline="\n")
    return tmp


class TestTheDigestIsEnforced(unittest.TestCase):
    def test_a_matching_artifact_is_accepted(self):
        with tempfile.TemporaryDirectory() as raw:
            root = _project(Path(raw), _manifest())
            self.assertIsNotNone(registry.ModelRegistry(root).promoted("exploit"))
            self.assertIsNotNone(
                linear.promoted("exploit", models_dir=root / "models"))

    def test_one_changed_byte_is_refused(self):
        """The failure this exists for: weights swapped after evaluation."""
        with tempfile.TemporaryDirectory() as raw:
            root = _project(Path(raw), _manifest())
            ranker = root / "models" / "exploit" / "v1" / "ranker.json"
            data = json.loads(ranker.read_text(encoding="utf-8"))
            data["weights"]["a"] = 99.0          # the same ids, a new opinion
            ranker.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n",
                              encoding="utf-8", newline="\n")
            manifest = json.loads(
                (root / "models" / "exploit" / "v1" / "manifest.json")
                .read_text(encoding="utf-8"))
            # The registry stamps this in `candidates()`; a dict read by hand
            # has to carry it too, or "ranker.json" resolves against the repo.
            manifest["_manifest_dir"] = str(
                root / "models" / "exploit" / "v1")
            problem = registry.digest_problem(manifest)
            self.assertIn("digest mismatch", problem)
            self.assertIsNone(registry.ModelRegistry(root).promoted("exploit"))
            self.assertIsNone(
                linear.promoted("exploit", models_dir=root / "models"))

    def test_the_refusal_names_both_digests(self):
        with tempfile.TemporaryDirectory() as raw:
            root = _project(Path(raw), _manifest())
            ranker = root / "models" / "exploit" / "v1" / "ranker.json"
            declared = _sha(ranker)
            ranker.write_bytes(ranker.read_bytes() + b" ")
            manifest = json.loads(
                (root / "models" / "exploit" / "v1" / "manifest.json")
                .read_text(encoding="utf-8"))
            manifest["_manifest_dir"] = str(
                root / "models" / "exploit" / "v1")
            problem = registry.digest_problem(manifest)
            self.assertIn(declared[:16], problem)
            self.assertIn(_sha(ranker)[:16], problem)

    def test_an_adapter_directory_is_hashed_too(self):
        """LoRA weights are a directory: a changed byte must still be seen."""
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            folder = root / "models" / "finding" / "v1"
            (folder / "adapter").mkdir(parents=True)
            (folder / "adapter" / "b.bin").write_bytes(b"weights")
            (folder / "adapter" / "a.json").write_text("{}", encoding="utf-8")
            manifest = _manifest(phase="finding", ranker=None, adapter="adapter",
                                 kind="lora")
            del manifest["ranker"]
            manifest["sha256"] = registry.artifact_digest(
                {"adapter": "adapter", "_manifest_dir": str(folder)})
            (folder / "manifest.json").write_text(
                json.dumps(manifest, indent=2), encoding="utf-8")
            self.assertIsNotNone(registry.ModelRegistry(root).promoted("finding"))

            (folder / "adapter" / "b.bin").write_bytes(b"weightz")
            self.assertIsNone(registry.ModelRegistry(root).promoted("finding"))

    def test_the_trainer_and_the_registry_hash_a_directory_the_same_way(self):
        """One scheme, or every promoted adapter is refused for the wrong reason.

        The runtime cannot import `training/` (not shipped), so the tree digest
        exists twice: `training.manifest.sha256_tree` writes it into the
        manifest and `registry._tree_digest` checks it. If the two drift, a
        correctly measured adapter is refused as tampered — the failure is
        silent until someone promotes one.
        """
        from training import manifest as training_manifest

        with tempfile.TemporaryDirectory() as raw:
            folder = Path(raw) / "adapter"
            (folder / "nested").mkdir(parents=True)
            (folder / "adapter_model.safetensors").write_bytes(b"\x00weights\x00")
            (folder / "nested" / "tokenizer.json").write_text(
                '{"a": 1}\n', encoding="utf-8", newline="\n")
            self.assertEqual(training_manifest.sha256_tree(folder),
                             registry._tree_digest(folder))
            self.assertNotEqual(training_manifest.sha256_tree(folder),
                                training_manifest.sha256_file(
                                    folder / "adapter_model.safetensors"),
                                "the weights file alone must not be the tree "
                                "digest: the tokenizer is part of the model")

    def test_the_directory_digest_does_not_depend_on_write_order(self):
        with tempfile.TemporaryDirectory() as raw:
            first = Path(raw) / "one"
            second = Path(raw) / "two"
            for base, order in ((first, ("b", "a")), (second, ("a", "b"))):
                base.mkdir(parents=True)
                for name in order:
                    (base / name).write_bytes(name.encode())
            self.assertEqual(registry._tree_digest(first),
                             registry._tree_digest(second))


class TestTheDigestIsByteStable(unittest.TestCase):
    """The cause of the 2026-11-06 mismatch: line endings, not tampering."""

    def test_identical_bytes_hash_identically(self):
        with tempfile.TemporaryDirectory() as raw:
            first = Path(raw) / "a.json"
            second = Path(raw) / "nested" / "b.json"
            second.parent.mkdir()
            for path in (first, second):
                path.write_text(_ranker_json(), encoding="utf-8", newline="\n")
            self.assertEqual(_sha(first), _sha(second))
            self.assertEqual(registry._file_digest(first),
                             registry._file_digest(second))

    def test_a_crlf_copy_is_not_the_measured_artifact(self):
        """A platform that rewrites newlines changed the bytes it promised.

        This is deliberately a REFUSAL, not a normalisation: hashing the text
        instead of the file would accept a rewrite of the artifact, and
        refusing is the only behaviour that keeps the digest meaningful. The
        fix belongs in `.gitattributes` + the writer, which is why the shipped
        model is asserted separately below.
        """
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            folder = root / "models" / "exploit" / "v1"
            folder.mkdir(parents=True)
            lf = folder / "ranker.json"
            lf.write_text(_ranker_json(), encoding="utf-8", newline="\n")
            manifest = _manifest(sha256=_sha(lf))
            manifest["_manifest_dir"] = str(folder)
            self.assertEqual(registry.digest_problem(manifest), "")

            lf.write_bytes(lf.read_bytes().replace(b"\n", b"\r\n"))
            self.assertIn("digest mismatch",
                          registry.digest_problem(manifest))

    def test_the_writers_do_not_translate_newlines(self):
        """`write_text` without `newline` is what broke the digest.

        Pinned against the source, because the bug only appears on a host
        whose `os.linesep` is not `\\n` — a Linux-only CI run would stay green
        while every Windows install was refused.
        """
        for relative in ("training/ranker.py", "training/net.py"):
            source = (Path(__file__).resolve().parent.parent / relative
                      ).read_text(encoding="utf-8")
            self.assertIn('newline="\\n"', source,
                          f"{relative} writes an artifact without a pinned "
                          f"newline: the recorded digest becomes host-specific")
            self.assertNotIn(
                'out.write_text(json.dumps', source,
                f"{relative} still writes the artifact with write_text(), "
                f"which applies os.linesep")


class TestTheShippedModelIsIntact(unittest.TestCase):
    def test_the_promoted_ranker_matches_its_manifest(self):
        """The real artifact: this is the check that was missing in production.

        Note for a failing local run: a working tree checked out BEFORE
        `models/** -text` landed still has CRLF in ranker.json. Re-checkout
        the file (`git rm --cached` + `git checkout --`) — do not relax this
        assertion, it is the whole point.
        """
        root = Path(__file__).resolve().parent.parent
        manifest = json.loads(
            (root / "models" / "exploit" / "ranker-2026-11-03" / "manifest.json")
            .read_text(encoding="utf-8"))
        manifest["_manifest_dir"] = str(
            root / "models" / "exploit" / "ranker-2026-11-03")
        self.assertEqual(registry.digest_problem(manifest), "")
        self.assertEqual(registry.manifest_errors(manifest, "exploit", root), [])
        self.assertIsNotNone(registry.ModelRegistry(root).promoted("exploit"))
        self.assertIsNotNone(linear.promoted("exploit"))


class TestMeasurementOnlyManifestsStillValidate(unittest.TestCase):
    def test_a_manifest_that_names_no_artifact_is_not_refused(self):
        """Hand-written benchmark fixtures owe no file, so they owe no digest.

        Tightening this would refuse the fixtures that measure the ladder, not
        a model that was served unverified.
        """
        data = _manifest(sha256="0" * 64)
        for key in ("ranker", "adapter", "kind"):
            data.pop(key, None)
        self.assertEqual(registry.manifest_errors(data, "exploit"), [])


if __name__ == "__main__":
    unittest.main()
