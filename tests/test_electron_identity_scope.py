"""The operator's OSINT scope, on the UI side of the wire.

There is no JS unit-test runner in this repo, so — like the remote-canvas and
allowlist-sync tests — these assert on the component SOURCE. What they pin:

  * the scope chips exist, in the operator's order, with "Other" reading as
    "not one of the five";
  * the chosen value reaches BOTH the run and the dry run under the exact
    wire key the backend reads (`platform`);
  * the store field the chips write is the one the payload reads, so the
    button the operator sees and the value the backend receives cannot drift;
  * the preview endpoint can never be handed `''`/`'other'` (it takes one
    concrete platform).
"""
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PANEL = os.path.join(ROOT, "electron", "src", "components", "AutoModePanel.tsx")
STORE = os.path.join(ROOT, "electron", "src", "store", "index.ts")
API = os.path.join(ROOT, "electron", "src", "lib", "api.ts")


def _src(path: str) -> str:
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


def test_the_chips_are_the_five_socials_plus_auto_and_other():
    src = _src(PANEL)
    assert ("const IDENTITY_SCOPES = ['auto', 'instagram', 'tiktok', 'x', "
            "'github',\n  'telegram', 'other'] as const") in src


def test_other_is_labelled_as_an_exclusion_not_a_platform():
    src = _src(PANEL)
    assert "everywhere except the 5 top socials" in src
    assert "Search everywhere except the 5 top socials" in src


def test_a_pinned_choice_says_the_other_networks_are_not_probed():
    src = _src(PANEL)
    assert "only — other platforms are not probed" in src


def test_the_run_payload_carries_the_scope_under_the_wire_key():
    src = _src(PANEL)
    assert "platform: autoMode.identityPlatform" in src
    # ... on the run AND on the dry run: a preview that disagreed with the
    # run would be worse than no preview at all
    assert src.count("platform: autoMode.identityPlatform") >= 2


def test_the_scope_control_appears_when_a_username_is_recognised():
    """The request was a field that SHOWS UP for a username, not a knob that
    sits there for every target type."""
    src = _src(PANEL)
    assert "const identityLooksLikeUsername = (value: string): boolean =>" in src
    assert "const showScopeChips = identityLooksLikeUsername(idUser)" in src
    assert "showScopeChips && (" in src
    # a non-default scope stays visible so it can always be undone
    assert "|| autoMode.identityPlatform !== ''" in src


def test_the_scope_line_above_launch_only_warns_when_a_scope_is_set():
    src = _src(PANEL)
    block = src[src.index("what the run will do with the identity"):][:400]
    assert "autoMode.identityPlatform !== ''" in block
    assert "scopeHint(idScope)" in block


def test_the_store_field_is_the_single_source_of_the_chips():
    src = _src(PANEL)
    # the chips derive their state from the store, never from a private
    # useState that could diverge from what is sent
    assert "autoMode.identityPlatform === ''" in src
    assert "setAutoMode({ identityPlatform: scopeValue(s) })" in src


def test_auto_travels_as_the_empty_string():
    src = _src(PANEL)
    assert "const scopeValue = (s: IdentityScope): string => (s === 'auto' ? '' : s)" in src


def test_the_preview_cannot_be_asked_for_a_non_single_platform():
    src = _src(PANEL)
    assert ("const idPlatform = idScope === 'auto' || idScope === 'other' ? '' "
            ": idScope") in src
    assert "if (!username || !previewable) return" in src


def test_the_store_declares_the_field_with_an_empty_default():
    src = _src(STORE)
    assert "identityPlatform: string" in src
    assert "identityPlatform: ''" in src


def test_both_api_payload_types_carry_the_optional_field():
    src = _src(API)
    assert "platform?: string" in src
    # one for the run, one for the dry run
    assert src.count("platform?: string") >= 2
