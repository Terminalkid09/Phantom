# Phishing chain — what actually works

Scope: the path `craft` → lure/page generation → `social/engine.py` campaign →
`deliverability.py` pre-flight → SMTP transport. Every row cites the code that
implements it, so this page can be checked instead of believed.

Short version: **the local half is complete and runs with zero configuration;
the send is gated on SMTP credentials and refuses instead of pretending.**

---

## 1. Works with zero external configuration

| Stage | What it does | Evidence |
|---|---|---|
| Lure / page generation | Builds the HTML lure and the tracked link (`ipgrab`, `pixel`, `beacon` link) | `phantom/modules/craft.py` (`do_craft`, page builders), `phantom/automation/social/tracker.py` |
| Tracker | Local HTTP endpoint that mints short links and records hits | `social/tracker.py::tracker_is_public`, link records consumed by `engine.py` |
| Persona | Display name, from-name and reply-to shaping; disposable inbox via GuerrillaMail (no account) | `social/persona.py::GuerrillaMail`, `carrier_sms_address` |
| Pretext scoring | Scores whether the message *reads* fake, reports the tell and the fix | `social/pretext_score.py::score_pretext`, used at `engine.py:1101` |
| Deliverability pre-flight | Identity / domain / content / channel checks against Gmail and M365 filters, graded, with the top fix | `social/deliverability.py` (module docstring lists every vector), called at `engine.py:1085` |
| Infra pre-flight | Checks the public URL, redirect and skin before a campaign leaves | `social/infra.py::infra_preflight` |
| Campaign state machine | Creates the campaign, one `CampaignTarget` per recipient, mints the link, tracks `sent` status | `social/engine.py::campaign` (`ct.mark("sent")` at `engine.py:1228`) |
| Skip with a reason | A phase whose transport is missing is skipped with an actionable message, not failed blindly | `social/transports.py::transport_status`, `_TRANSPORT_NEEDS` |

## 2. Needs configuration (credentials)

| Channel | Requirement | Evidence | What happens without it |
|---|---|---|---|
| Email | SMTP host/port/user/password (SMTP2GO or Brevo free tier) | `social/mailers.py::env_mail_config` (`transports.smtp.*` or `PHANTOM_SMTP_*`) | `Mailer._smtp_send` returns `False` when `config.username` is empty; `engine.py:1115` reports *"email delivery failed: configure PHANTOM_SMTP_USER/PHANTOM_SMTP_PASSWORD"* |
| SMS | SMTP **plus** a carrier gateway | `transports.py::_sms_ready` (`PHANTOM_SMS_CARRIER`) | channel not ready (`engine.py:2060`: *"carrier gateway unknown or SMTP unconfigured"*) |
| DM | `PHANTOM_DM_TRANSPORT`, or a Telegram bot token, or a Discord webhook | `transports.py::_dm_ready` | `dm_launch` is skipped by `_TRANSPORT_NEEDS` |
| Public lure URL | A domain, not a bare IP | `transports.py::_tracker_public`; lab escape hatch `_lab_lures_allowed` (`PHANTOM_ALLOW_UNSCOPED`) | bare-IP link is refused at lure build time, because it leaks the operator's IP |
| Breach / HIBP | `PHANTOM_HIBP_API_KEY` or `PHANTOM_BREACH_API` | `transports.py::transport_status` | `breach_check` reports "unknown" rather than an empty result |
| Public infra | `cloudflared` tunnel binary | `data/bin/cloudflared.exe`, `social/infra.py` | infra pre-flight reports not ready |

## 3. Not implemented — stated, not hidden

| Missing | Why it matters | Evidence |
|---|---|---|
| A real send has never been exercised by the suite | Tests inject a transport so they never send mail; a green suite proves the message is *built*, not delivered | `mailers.py` module docstring (*"Transport is injectable so tests never send"*) |
| SPF / DKIM / DMARC | The single highest-value deliverability fix, and the code cannot do it for you | `deliverability.py` docstring: *"Nothing here substitutes for SPF/DKIM/DMARC"* |
| Abstract DM providers | The base interface has no implementation; only the credential-backed channels send | `social_dm.py::send` (raises with an explicit interface message) |
| Reply-side automation | The chain polls tracker hits; it does not parse replies from an inbox | `engine.py` `poll_hits` / `harvest_campaign` are local phases only |
| Guaranteed inbox placement | Scores are **advisory**: a poorly graded message is still sent if the operator proceeds | `engine.py:1092` — a blocking grade produces a WARNING, not a refusal |

---

## Verdict

The phishing subsystem is a **lure factory with a credential-gated courier**.
Everything up to the send — page, link, persona, pretext, deliverability,
infra, campaign bookkeeping — works on a fresh checkout with zero config and is
scored *before* anything leaves the machine. The send itself is honest: without
SMTP credentials it returns `False` and says which variables to set, instead of
reporting a fake success.

What it cannot claim: that a message has ever been delivered end-to-end by this
codebase. With credentials it will attempt a genuine SMTP2GO/Brevo relay; on a
real Gmail or M365 tenant, a freshly registered domain with no SPF/DKIM/DMARC
and no sending reputation will land in Spam or be dropped, and the module says
exactly that rather than promising otherwise.
