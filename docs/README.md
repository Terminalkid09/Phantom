# Phantom — documentation index

This folder accumulated audits, reviews and reports over time. This index says
which document is CURRENT and which is a historical record, so a reader does
not act on a superseded finding.

## Canonical (read these)

| Document | What it is |
| --- | --- |
| [`Phantom.md`](Phantom.md) | Project specification / reference model. |
| [`ROADMAP.md`](ROADMAP.md) | Consolidated work roadmap. Where it disagrees with an older review, the roadmap (and `master_review.md`) is authoritative. |
| [`CHANGELOG.md`](CHANGELOG.md) | Notable changes per release. |
| [`beacon_platform_matrix.md`](beacon_platform_matrix.md) | Which beacon features actually build/run per platform. |
| [`CROSS_PLATFORM_BUILD_STATUS.md`](CROSS_PLATFORM_BUILD_STATUS.md) | Current cross-platform build status of the C++ beacon. |

## Audits & reviews (historical, dated)

These are point-in-time analyses. They are kept for provenance; check the
roadmap or the code before treating a finding as still open.

| Document | Scope | Date |
| --- | --- | --- |
| [`BEACON_AUDIT.md`](BEACON_AUDIT.md) | C++ beacon transport, Python C2, payload delivery, operator state. | 2026-08-21 |
| [`Phantom_dev_audit.md`](Phantom_dev_audit.md) | Security & architecture audit of `dev`. | — |
| [`master_review.md`](master_review.md) | Master review handoff (authoritative where reviews disagree). | — |
| [`REVIEW.md`](REVIEW.md) | Code review & analysis. | 2026-05-05 |
| [`manus.md`](manus.md) | Deep technical analysis + AutoMode redesign. | — |

## Verification / test reports (historical)

| Document | What it records |
| --- | --- |
| [`PHANTOM_VERIFICATION_REPORT.md`](PHANTOM_VERIFICATION_REPORT.md) | Verification run summary. |
| [`PHANTOM_FULL_MANUAL_TEST.md`](PHANTOM_FULL_MANUAL_TEST.md) | Manual test report against Metasploitable2. |

## Conventions

* Do not add a new audit as a top-level `docs/*.md` without an entry here.
* Prefer updating an existing document over adding a near-duplicate; the pile
  of overlapping reviews is exactly what this index exists to tame.
* The repository root README is the entry point for users; this index is for
  contributors looking for a specific analysis.
