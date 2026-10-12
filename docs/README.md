# Phantom — documentation index

This folder accumulated audits, reviews and reports over time. This index says
which document is CURRENT and which is a historical record, so a reader does
not act on a superseded finding.

**Version lines right now** — so a version number read in any of these files
can be placed: `dev` is the **v3.0.0** line (in development, not tagged yet)
and this folder documents that line; `main` is the released line at **v2.0.0**.
The tags are `v1.0.0`, `v1.1.0`, `v2.0.0`. The changelog lives at the
**repository root** ([`../CHANGELOG.md`](../CHANGELOG.md)) — the `CHANGELOG.md`
in *this* folder is the frozen 1.x one.

## Canonical (read these)

| Document | What it is |
| --- | --- |
| [`Phantom.md`](Phantom.md) | Project specification / reference model. |
| [`ROADMAP.md`](ROADMAP.md) | Consolidated work roadmap. Where it disagrees with an older review, the roadmap (and `master_review.md`) is authoritative. |
| [`THREAT_MODEL.md`](THREAT_MODEL.md) | What Phantom defends (the operator and the engagement), from whom, and — explicitly — what it does not defend. |
| [`beacon_platform_matrix.md`](beacon_platform_matrix.md) | Which beacon features actually build/run per platform (the live contract). |

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
| [`ManusReview.md`](ManusReview.md) | Independent review: architecture, C2, AutoMode, gaps. | — |
| [`ManusOpenCode.md`](ManusOpenCode.md) | AutoMode/handoff redesign proposal. | — |
| [`AutoModeBrief.md`](AutoModeBrief.md) | AutoMode + tool-discovery brief. Its P0/P1 items are now IMPLEMENTED in `phantom/automation/` — read it as the design intent, and check the code/roadmap for current status, not as an open-work list. | 2026-10-05 |
| [`CROSS_PLATFORM_BUILD_STATUS.md`](CROSS_PLATFORM_BUILD_STATUS.md) | Early cross-platform beacon build snapshot ("166 tests"); superseded by `beacon_platform_matrix.md` and the CI beacon jobs. | — |
| [`CHANGELOG.md`](CHANGELOG.md) | **Legacy and frozen at 1.1.0** — the 1.x changelog, kept for provenance. The current one is [`../CHANGELOG.md`](../CHANGELOG.md); do not add entries to this file. | — |

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
