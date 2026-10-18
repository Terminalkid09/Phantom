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
| [`ROADMAP.md`](ROADMAP.md) | Consolidated work roadmap. Where it disagrees with an older review, the roadmap is authoritative (the code wins over both). |
| [`THREAT_MODEL.md`](THREAT_MODEL.md) | What Phantom defends (the operator and the engagement), from whom, and — explicitly — what it does not defend. |
| [`beacon_platform_matrix.md`](beacon_platform_matrix.md) | Which beacon features actually build/run per platform (the live contract). |
| [`AutoModeBenchmark.md`](AutoModeBenchmark.md) | How auto-mode is MEASURED (ground truth scenarios, failure injection, what the numbers do and do not prove) and how to run the suite. |
| [`service_units.md`](service_units.md) | `--print-service` / `--install-service` / `--uninstall-service`: how a run survives a reboot, and what the install writes, audits and verifies. |
| [`c2d.md`](c2d.md) | The Go data plane (`c2d/`): what it ports, what stays in Python (answered `501`), and how to run it. |

**Test counts.** Only the repository root [`README.md`](../README.md) states a
current test count, and it is contract-tested against the tree
(`tests/test_readme_contract.py`). Any number in a dated document here
(3.319 / 3.710 / 3.881 / 166 …) is a snapshot of the day it was written —
never a figure to quote as today's.

## Audits & reviews (historical, dated)

These are point-in-time analyses. They are kept for provenance; check the
roadmap or the code before treating a finding as still open.

| Document | Scope | Date |
| --- | --- | --- |
| [`Audit_2026-10-13.md`](Audit_2026-10-13.md) | Verification of the 12-Oct review + deep audit of core / C2+beacon / AutoMode / handoff / UI / deps / sessions+reports+.pm / docs. All findings are measured at commit `b8a79eab`. | 2026-10-13 |
| [`Audit_Fixes_2026-10-13.md`](Audit_Fixes_2026-10-13.md) | **The AFTER document**: each finding of `Audit_2026-10-13.md` mapped to the fix and to the test that fails without it, a second pass that re-reads the audit point by point (what is closed, what was only partial, what is open by nature), the regressions the fixes surfaced, the measured verification numbers, a `.gitignore` hygiene note, the updated grade table, and the list of every file this work created. Where the two disagree, this one wins. | 2026-10-13 |
| [`BEACON_AUDIT.md`](BEACON_AUDIT.md) | C++ beacon transport, Python C2, payload delivery, operator state. | 2026-08-21 |
| [`Phantom_dev_audit.md`](Phantom_dev_audit.md) | Security & architecture audit of `dev`. | — |
| [`master_review.md`](master_review.md) | **Reviewer INSTRUCTIONS, not findings** — a handoff prompt written for an external model (what to verify, how to classify it). Its claims are working hypotheses; do not quote them as results. | — |
| [`REVIEW.md`](REVIEW.md) | Code review & analysis. | 2026-05-05 |
| [`manus.md`](manus.md) | Deep technical analysis + AutoMode redesign. | — |
| [`ManusReview.md`](ManusReview.md) | Independent review: architecture, C2, AutoMode, gaps. Point-in-time at commit `b751fe6`; **superseded** where it overlaps by `Audit_2026-10-13.md` (re-prove a finding from it before treating it as open). | 2026-10-05 |
| [`ManusOpenCode.md`](ManusOpenCode.md) | AutoMode/handoff redesign proposal. | — |
| [`AutoModeBrief.md`](AutoModeBrief.md) | AutoMode + tool-discovery brief. Its P0/P1 items are now IMPLEMENTED in `phantom/automation/` — read it as the design intent, and check the code/roadmap for current status, not as an open-work list. | 2026-10-05 |
| [`CROSS_PLATFORM_BUILD_STATUS.md`](CROSS_PLATFORM_BUILD_STATUS.md) | Early cross-platform beacon build snapshot ("166 tests"); superseded by `beacon_platform_matrix.md` and the CI beacon jobs. | — |
| [`CHANGELOG.md`](CHANGELOG.md) | **Legacy and frozen at 1.1.0** — the 1.x changelog, kept for provenance. The current one is [`../CHANGELOG.md`](../CHANGELOG.md); do not add entries to this file. | — |

## Verification / test reports (historical)

| Document | What it records |
| --- | --- |
| [`Live_Test_2026-10-17_18.md`](Live_Test_2026-10-17_18.md) | **Two-day operator-workflow validation** (2026-10-17/18): the real `generate` → second terminal → C2 dropper flow, the three-defect kill bug (greedy `\x02E`, raw control bytes in the result JSON, resumed status stuck at `EXITED`), the six MediaFoundation camera root causes and the first real frame through the dropper, `persist`/`unpersist`, auto-mode on `.18` (1 000/1 000 filtered) and the mobile profile on `.6`, passive identity OSINT with its honest limits, and the per-feature scorecard. |
| [`Live_Retest_2026-10-16.md`](Live_Retest_2026-10-16.md) | **The after-document for `Live_Test_2026-10-16.md`**: why `.6`/`.18` were invisible (the network mapper never used the WSL tool bridge and fell back to ICMP), the seven fixes that followed (`netmap` tool resolution + TCP probes + ARP-cache discovery/liveness + `/32` scope + broadcast-MAC label, `c2_endpoint_status` honouring the advertised endpoint), the lab kill chain driven live to the internal root flag, the C2 half verified on the operator's machine (listener → check-in → `whoami`/`shell id` → `set-sleep` → `exit` kills the beacon), the findings left open (Defender blocking the Windows PE, `queue_task` accepting an empty beacon id, the WSL toolbox gaps) and what was deliberately not tested. |
| [`Live_Test_2026-10-16.md`](Live_Test_2026-10-16.md) | **Live session on the operator's own machine and LAN** (2026-10-16, `dev`): Electron typecheck/build/package + installer, the network mapping feature driven end-to-end through the real app (discovery, host store, rendered graph), beacon cross-build smoke for Windows/Linux, the container lab brought up and its entry points re-verified, and the four defects the run surfaced (broken `/api/c2/artifacts`, `POST /api/network/scan` ignoring a bare-IP target, inconsistent version strings, invisible scan status). Per-feature scorecard, blockers for the phases that were handed to the operator, and the runbook for them are in the document. |
| [`PHANTOM_VERIFICATION_REPORT.md`](PHANTOM_VERIFICATION_REPORT.md) | Verification run summary. |
| [`PHANTOM_FULL_MANUAL_TEST.md`](PHANTOM_FULL_MANUAL_TEST.md) | Manual test report against Metasploitable2. |

## Conventions

* Do not add a new audit as a top-level `docs/*.md` without an entry here.
* Prefer updating an existing document over adding a near-duplicate; the pile
  of overlapping reviews is exactly what this index exists to tame.
* The repository root README is the entry point for users; this index is for
  contributors looking for a specific analysis.
