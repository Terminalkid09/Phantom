# Phantom — documentation index

This folder holds the **current truth only**: specifications, contracts and
runbooks that a reader is meant to act on today. Point-in-time material —
audits, reviews, live-test transcripts — is not kept here: it stops being true
the day after it is written, and a reader cannot tell when. That history lives
in [`../CHANGELOG.md`](../CHANGELOG.md) and in git.

**Version lines** — `dev` is the **v3.0.0** line (in development, not tagged
yet) and this folder documents that line; `main` is the released line at
**v2.0.0**. Tags: `v1.0.0`, `v1.1.0`, `v2.0.0`. The changelog is at the
repository root.

## Canonical (read these)

| Document | What it is |
| --- | --- |
| [`ROADMAP.md`](ROADMAP.md) | Consolidated work roadmap. Where it disagrees with a review, the roadmap wins; the code wins over both. |
| [`Action_Plan_2026-10-31.md`](Action_Plan_2026-10-31.md) | Current action plan: what closed on 31 Oct with its measurement, the open phases and an acceptance criterion for each. |
| [`THREAT_MODEL.md`](THREAT_MODEL.md) | What Phantom defends (the operator and the engagement), from whom, and — explicitly — what it does not defend. |
| [`beacon_platform_matrix.md`](beacon_platform_matrix.md) | Which beacon features actually build/run per platform (the live contract, CI-checked). |
| [`AutoModeBenchmark.md`](AutoModeBenchmark.md) | How auto-mode is MEASURED (ground-truth scenarios, failure injection, what the numbers do and do not prove) and how to run the suite. |
| [`service_units.md`](service_units.md) | `--print-service` / `--install-service` / `--uninstall-service`: how a run survives a reboot, and what the install writes, audits and verifies. |
| [`c2d.md`](c2d.md) | The Go data plane (`c2d/`): what it ports, what stays in Python (answered `501`), and how to run it. |
| [`PHISHING_STATUS.md`](PHISHING_STATUS.md) | What the phishing surface does today, what is credential-gated, and what is explicitly out of scope (SPF/DKIM/DMARC, end-to-end delivery). |
| [`COMMAND_REFERENCE.md`](COMMAND_REFERENCE.md) | Every shell, module, C2 and AUTO-MODE command with what it does. **Generated** from the live registries — regenerate it, never hand-edit it. |

**Test counts.** Only the repository root [`README.md`](../README.md) states a
current test count, and it is contract-tested against the tree
(`tests/test_readme_contract.py`). A number in any other document is a snapshot
of the day it was written.

## Conventions

* **`docs/` is for current truth.** A dated audit, review or live-test
  transcript belongs in `CHANGELOG.md` (what changed) and in git history (the
  full text), not in a new file here. `tests/test_readme_contract.py` enforces
  this: a point-in-time page added to `docs/` fails the suite.
* **One document per subject.** Prefer updating an existing page over adding a
  near-duplicate — a pile of overlapping reviews is exactly what forced this
  index to exist in the first place.
* **English only**, and every generated page is marked as generated.
* **Adding a document means adding a row here.** Both directions are
  contract-tested: no unindexed file, no row pointing at a file that is gone.
* The repository root README is the entry point for users; this index is for
  contributors looking for a specific analysis.
