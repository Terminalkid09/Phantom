"""
persona.py — throwaway attacker identity + coherent social profile.

A Persona is a use-and-discard identity: random name, a disposable email
address (temp-mail / guerrilla-mail free APIs, rate-limited so a fallback
chain is used), and an SMS channel via email-to-SMS carrier gateways.

A PersonaProfile is the *credible cover* that makes the identity believable
on social platforms: a coherent first/last name, age band consistent with
the job title, a city, interests, a bio and an avatar picture. The profile
is what a target sees before they open a DM — an empty profile with a
random name is the #1 reason a lure gets reported.

Avatar strategy (offline-first, zero mandatory config):
  1. PHANTOM_PERSONA_AVATAR=randomuser -> fetch a free portrait photo from
     randomuser.me (no key), cached locally under data/personas/avatars/.
  2. Default: Pillow-generated avatar (gradient + initials) — fully
     offline, deterministic from the profile seed.
  3. Pillow missing -> avatar stays None; the profile is still coherent.

Everything that touches the network is an injected transport so the unit
tests stay offline and the operator can point at a different provider.
"""

from __future__ import annotations

import os
import random
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

# ---------------------------------------------------------------------------
# disposable mail providers (free)
# ---------------------------------------------------------------------------

class TempMailProvider:
    """Interface for a disposable inbox provider."""

    def create(self) -> Dict[str, str]:
        """Return {address, email_id} for a fresh inbox."""
        raise NotImplementedError

    def fetch_inbox(self, email_id: str, timeout: float = 30.0) -> List[Dict[str, str]]:
        """Return list of {id, from_, subject, body} — may block for new mail."""
        raise NotImplementedError

    def destroy(self, email_id: str) -> None:
        """Forget the inbox (use-and-discard)."""
        raise NotImplementedError


class GuerrillaMail(TempMailProvider):
    """Guerrilla Mail public API (no key required, rate-limited)."""

    BASE = "https://api.guerrillamail.com/ajax.php"

    def __init__(self, fetcher: Optional[Callable] = None) -> None:
        # fetcher(uri) -> json dict, injectable for tests
        self._fetch = fetcher or self._default_fetch

    @staticmethod
    def _default_fetch(uri: str) -> dict:
        import requests
        return requests.get(uri, timeout=15).json()

    def _call(self, action: str, **params) -> dict:
        import urllib.parse
        uri = f"{self.BASE}?f={action}&" + urllib.parse.urlencode(params)
        return self._fetch(uri)

    def create(self) -> Dict[str, str]:
        data = self._call("get_email_address")
        return {"address": data.get("email_addr", ""), "email_id": str(data.get("email_id", ""))}

    def fetch_inbox(self, email_id: str, timeout: float = 30.0) -> List[Dict[str, str]]:
        data = self._call("fetch_email", email_id=email_id, timeout=5)
        mails = []
        for m in data.get("list", []):
            mails.append({
                "id": m.get("mail_id"),
                "from_": m.get("mail_from", ""),
                "subject": m.get("mail_subject", ""),
                "body": m.get("mail_body", "") or m.get("body", ""),
            })
        return mails

    def destroy(self, email_id: str) -> None:
        self._call("forget_email", email_id=email_id)


# ---------------------------------------------------------------------------
# persona
# ---------------------------------------------------------------------------

_FIRST = ["Alex", "Jordan", "Taylor", "Casey", "Riley", "Morgan", "Drew", "Sam",
          "Jamie", "Avery", "Quinn", "Peyton"]
_LAST = ["Reed", "Hayes", "Brooks", "Cole", "Wade", "Kent", "Marsh", "Lane",
         "Stone", "Page", "Fox", "Frost"]
_DOMAINS = ["@guerrillamail.com", "@grr.la", "@guerrillamailblock.com"]


@dataclass
class Persona:
    name: str
    email: str
    email_id: str = ""
    carrier_sms: Optional[str] = None  # email address reaching the victim's phone
    provider: Optional[TempMailProvider] = None

    # -- constructors ----------------------------------------------------

    @classmethod
    def generate(cls, provider: Optional[TempMailProvider] = None) -> "Persona":
        """Build a fresh persona from a random name + disposable inbox."""
        name = f"{random.choice(_FIRST)} {random.choice(_LAST)}"
        if provider is None:
            provider = GuerrillaMail()
        try:
            inbox = provider.create()
            email = inbox["address"] or f"{name.split()[0].lower()}{random.randint(10, 99)}@grr.la"
            email_id = inbox["email_id"]
        except Exception:
            email = f"{name.split()[0].lower()}{random.randint(10, 99)}{random.choice(_DOMAINS)}"
            email_id = ""
        return cls(name=name, email=email, email_id=email_id, provider=provider)

    # -- inbox -------------------------------------------------------------

    def wait_for_message(self, subject_hint: str = "", timeout: float = 60.0) -> Optional[Dict[str, str]]:
        """Poll the inbox for an incoming message (e.g. verification link)."""
        if self.provider is None or not self.email_id:
            return None
        import time
        deadline = time.time() + timeout
        seen: set = set()
        while time.time() < deadline:
            try:
                for m in self.provider.fetch_inbox(self.email_id, timeout=5):
                    if m["id"] in seen:
                        continue
                    seen.add(m["id"])
                    if not subject_hint or subject_hint.lower() in m["subject"].lower():
                        return m
            except Exception:
                pass
            time.sleep(5)
        return None

    def destroy(self) -> None:
        if self.provider is not None and self.email_id:
            try:
                self.provider.destroy(self.email_id)
            except Exception:
                pass

    def to_finding(self, target: str):
        from phantom.automation.belief import Finding
        return Finding(kind="persona", key=self.email,
                       value={"name": self.name, "email": self.email,
                              "carrier_sms": self.carrier_sms},
                       confidence=0.9, source="persona", target=target)


# ---------------------------------------------------------------------------
# persona profile (coherent social cover)
# ---------------------------------------------------------------------------

# first names, Italian + international mix (the persona should feel local to
# the engagement; gender balanced so the generator picks freely)
_PROFILE_FIRST = {
    "m": ["Marco", "Luca", "Andrea", "Matteo", "Alessandro", "Davide", "Leo",
          "Jonas", "Lukas", "Elias", "Tom", "Max", "Daniel", "Adam"],
    "f": ["Giulia", "Sara", "Elena", "Chiara", "Anna", "Martina", "Alice",
          "Emma", "Nora", "Mila", "Lena", "Sophie", "Clara", "Mia"],
}
_PROFILE_LAST = ["Rossi", "Bianchi", "Ferrari", "Esposito", "Romano", "Colombo",
                 "Ricci", "Marino", "Greco", "Conti", "Keller", "Muller",
                 "Janssen", "Novak", "Weber", "Silva", "Costa", "Berg"]

# job tiers -> plausible age band + skill flavor. Age and job must not
# contradict each other: an "intern" is never 47, a "CTO" is never 19.
_JOB_TIERS = [
    {"titles": ["Intern", "Junior Designer", "Junior Developer", "Trainee"],
     "age": (19, 25), "seniority": "junior"},
    {"titles": ["Graphic Designer", "UX Designer", "Developer", "Marketing Specialist",
                 "Photographer", "Video Editor", "Community Manager"],
     "age": (24, 35), "seniority": "mid"},
    {"titles": ["Senior Developer", "Product Designer", "Art Director", "Brand Manager",
                 "Creative Lead", "Motion Designer", "Growth Manager"],
     "age": (30, 44), "seniority": "senior"},
    {"titles": ["Head of Design", "Engineering Lead", "Creative Director",
                 "Marketing Director", "Startup Founder"],
     "age": (35, 52), "seniority": "lead"},
]

_CITIES_IT = ["Milano", "Roma", "Torino", "Bologna", "Firenze", "Napoli", "Verona", "Padova"]
_CITIES_INTL = ["Berlin", "Amsterdam", "Lisbon", "Vienna", "Prague", "Dublin", "Zurich", "Barcelona"]

_INTERESTS = ["photography", "hiking", "coffee brewing", "indie music", "urban sketching",
              "cycling", "board games", "bouldering", "film photography", "cooking",
              "trail running", "electronic music", "street art", "plant care"]
_HOBBIES = ["shooting 35mm film", "testing coffee shops", "planning weekend hikes",
            "sketching at the park", "tuning my bike", "hunting for vinyl", "baking sourdough",
            "playing old synth sounds", "walking the dog at sunrise", "organizing game nights"]

# non-professional audiences: a 14-year-old target does not believe a
# "Senior Developer" who sends a LinkedIn recruiter DM — the persona must
# match the target's world (same school, same age, same interests).
_AUDIENCES = {
    "middle":     {"age": (11, 14), "label": "student", "grade": "middle school"},
    "high":       {"age": (14, 19), "label": "student", "grade": "high school"},
    "university": {"age": (18, 25), "label": "student", "grade": "university"},
    "professional": None,  # job-tier driven (existing behavior)
}
_SCHOOLS_IT = ["Liceo Scientifico", "Liceo Classico", "ITIS", "Liceo Linguistico",
               "Istituto Tecnico Economico", "Scuola Media"]
_SCHOOLS_INTL = ["High School", "Secondary School", "Community College", "University"]
_STUDENT_INTERESTS = ["football", "basketball", "gaming", "anime", "skateboarding",
                      "music production", "fashion", "photography", "volleyball", "drawing"]
_STUDENT_HOBBIES = ["playing fifa", "editing videos", "going to the gym", "watching anime",
                    "sketching in class", "playing bass", "street basketball",
                    "collecting sneakers", "mixing beats", "riding the skateboard"]

# gradients per gender -> two pleasant colors for the avatar backdrop
_AVATAR_COLORS = {
    "m": [("#5b7cfa", "#00c6fb"), ("#4a00e0", "#8e2de2"), ("#0f2027", "#2c5364")],
    "f": [("#f953c6", "#b91d73"), ("#ee9ca7", "#ffdde1"), ("#a18cd1", "#fbc2eb")],
}


@dataclass
class PersonaProfile:
    """A coherent, believable social cover for a throwaway identity."""

    name: str
    gender: str = "m"
    age: int = 24
    job_title: str = "Developer"
    company: str = ""
    audience: str = "professional"   # middle | high | university | professional
    school: str = ""                 # set for student audiences
    city: str = "Milano"
    country: str = "Italy"
    interests: List[str] = field(default_factory=list)
    bio: str = ""
    avatar_path: Optional[str] = None   # local file, empty when unavailable
    seed: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name, "gender": self.gender, "age": self.age,
            "job_title": self.job_title, "company": self.company,
            "audience": self.audience, "school": self.school,
            "city": self.city, "country": self.country,
            "interests": list(self.interests), "bio": self.bio,
            "avatar": self.avatar_path or "", "seed": self.seed,
        }

    def to_finding(self, target: str):
        from phantom.automation.belief import Finding
        return Finding(kind="persona_profile", key=self.name,
                       value=self.to_dict(), confidence=0.85,
                       source="persona", target=target)


def _job_tier(seed: int) -> dict:
    rnd = random.Random(seed)
    return rnd.choice(_JOB_TIERS)


def generate_profile(seed: Optional[int] = None, locale: str = "en",
                     gender: Optional[str] = None,
                     name: Optional[str] = None,
                     audience: str = "professional") -> PersonaProfile:
    """Build a coherent profile: every field is consistent with the rest.

    * age always falls inside the audience's band (an intern is never 47, a
      high-schooler is never 31)
    * city/country match the locale (it -> Italian city, else international)
    * student audiences get a school + age-appropriate interests/bio
    * interests are drawn from one pool and the bio references them
    * same seed -> identical profile (tests, reproducible campaigns)
    """
    if seed is None:
        seed = random.randint(0, 2 ** 31)
    rnd = random.Random(seed)
    g = gender or rnd.choice(["m", "f"])
    first = rnd.choice(_PROFILE_FIRST[g])
    if name:
        parts = name.split()
        first = parts[0]
    last = rnd.choice(_PROFILE_LAST)
    if locale == "it":
        city, country = rnd.choice(_CITIES_IT), "Italy"
    else:
        city, country = rnd.choice(_CITIES_INTL), "Europe"

    audience = (audience or "professional").strip().lower()
    if audience not in _AUDIENCES or audience == "professional":
        # existing job-tier path
        tier = _job_tier(seed)
        age = rnd.randint(*tier["age"])
        interests = rnd.sample(_INTERESTS, k=rnd.randint(2, 3))
        hobby = rnd.choice(_HOBBIES)
        bio = (
            f"{first} {last} - {tier['titles'][0].lower()} based in {city}. "
            f"Into {interests[0]} and {interests[1]}. "
            f"When I'm not working you'll find me {hobby}. "
            "DM for collabs."
        )
        return PersonaProfile(
            name=f"{first} {last}", gender=g, age=age,
            job_title=tier["titles"][0], city=city, country=country,
            audience="professional", interests=interests, bio=bio, seed=seed)

    # student audiences: age band + school + age-appropriate content
    meta = _AUDIENCES[audience]
    age = rnd.randint(*meta["age"])
    school = rnd.choice(_SCHOOLS_IT if locale == "it" else _SCHOOLS_INTL)
    interests = rnd.sample(_STUDENT_INTERESTS, k=rnd.randint(2, 3))
    hobby = rnd.choice(_STUDENT_HOBBIES)
    if audience == "middle":
        bio = (f"Hey, I'm {first} - {age}, {city}. Into {interests[0]} "
               f"and {interests[1]}.")
    elif audience == "university":
        bio = (f"{first} {last} - student at {school}, {city}. "
               f"{interests[0].capitalize()} and {interests[1]}. "
               "DM for collabs.")
    else:  # high
        bio = (f"{first} {last} - {age}, {school}, {city}. "
               f"Into {interests[0]} and {interests[1]}. DM for collabs.")
    return PersonaProfile(
        name=f"{first} {last}", gender=g, age=age,
        job_title=f"Student at {school}", company=school, audience=audience,
        school=school, city=city, country=country,
        interests=interests, bio=bio, seed=seed)


def _avatar_cache_dir() -> str:
    base = os.getenv("PHANTOM_DATA_DIR", "data")
    path = os.path.join(base, "personas", "avatars")
    try:
        os.makedirs(path, exist_ok=True)
    except OSError:
        pass
    return path


def generate_avatar(profile: PersonaProfile) -> Optional[str]:
    """Create (or fetch) a profile picture for the persona.

    Order: PHANTOM_PERSONA_AVATAR=randomuser -> fetch a free portrait photo
    (no key) and cache it; otherwise render an offline PIL avatar
    (gradient + initials). Returns a local path, or None when neither is
    possible (e.g. Pillow not installed). Never raises.
    """
    source = os.getenv("PHANTOM_PERSONA_AVATAR", "offline").strip().lower()
    if source == "randomuser":
        path = _fetch_randomuser_avatar(profile)
        if path:
            return path
    return _render_pil_avatar(profile)


def _render_pil_avatar(profile: PersonaProfile, size: int = 512) -> Optional[str]:
    """Offline gradient + initials avatar. Deterministic per profile seed."""
    try:
        from PIL import Image, ImageDraw, ImageFont
    except Exception:
        return None
    try:
        rnd = random.Random(profile.seed)
        c1, c2 = rnd.choice(_AVATAR_COLORS[profile.gender])
        c1 = tuple(int(c1.lstrip("#")[i:i + 2], 16) for i in (0, 2, 4))
        c2 = tuple(int(c2.lstrip("#")[i:i + 2], 16) for i in (0, 2, 4))
        img = Image.new("RGB", (size, size))
        px = img.load()
        for y in range(size):
            t = y / (size - 1)
            col = tuple(int(c1[i] + (c2[i] - c1[i]) * t) for i in range(3))
            for x in range(size):
                px[x, y] = col
        draw = ImageDraw.Draw(img)
        initials = "".join(p[0] for p in profile.name.split()[:2]).upper()
        font = None
        for name in ("arialbd.ttf", "DejaVuSans-Bold.ttf", "segoeuib.ttf"):
            try:
                font = ImageFont.truetype(name, size // 3)
                break
            except Exception:
                continue
        if font is None:
            font = ImageFont.load_default()
        bbox = draw.textbbox((0, 0), initials, font=font)
        w, h = bbox[2] - bbox[0], bbox[3] - bbox[1]
        draw.text(((size - w) / 2 - bbox[0], (size - h) / 2 - bbox[1]),
                  initials, fill=(255, 255, 255, 255), font=font)
        path = os.path.join(_avatar_cache_dir(), f"{profile.seed}_{profile.gender}.png")
        img.save(path, "PNG")
        return path
    except Exception:
        return None


def _fetch_randomuser_avatar(profile: PersonaProfile) -> Optional[str]:
    """Fetch a free portrait photo from randomuser.me (no API key). Cached
    locally; any failure falls through to the offline renderer."""
    import urllib.request
    url = (f"https://randomuser.me/api/?gender={profile.gender}"
           f"&nat=it,de,fr,gb,us&noinfo")
    try:
        with urllib.request.urlopen(url, timeout=15) as resp:
            import json
            data = json.loads(resp.read().decode("utf-8", "ignore"))
        pic = data["results"][0]["picture"]["large"]
        req = urllib.request.Request(pic, headers={"User-Agent": "Phantom/3"})
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw = resp.read()
        ext = "jpg"
        path = os.path.join(_avatar_cache_dir(), f"{profile.seed}_{profile.gender}.{ext}")
        with open(path, "wb") as f:
            f.write(raw)
        return path
    except Exception:
        return None


# ---------------------------------------------------------------------------
# carrier SMS gateways (email -> SMS)
# ---------------------------------------------------------------------------

CARRIER_GATEWAYS = {
    "verizon": "@vtext.com",
    "att": "@txt.att.net",
    "tmobile": "@tmomail.net",
    "sprint": "@messaging.sprintpcs.com",
    "boost": "@sms.myboostmobile.com",
    "cricket": "@sms.cricketwireless.net",
    "metropcs": "@mymetropcs.com",
    "uscellular": "@email.uscc.net",
    "vodafone": "@vodafone.es",
    "tim": "@tim.it",
    "wind": "@sms.windmobile.ca",
    "orange": "@orange.net",
}

# phonenumbers.carrier returns human-readable names ("AT&T Mobility",
# "Verizon Wireless", …) — map them to the gateway keys above so SMS
# delivery can resolve a carrier from the phone number alone.
_CARRIER_ALIASES = {
    "at&t": "att", "at&t mobility": "att", "att": "att",
    "verizon": "verizon", "verizon wireless": "verizon",
    "t-mobile": "tmobile", "t-mobile usa": "tmobile", "tmobile": "tmobile",
    "sprint": "sprint", "boost mobile": "boost",
    "cricket wireless": "cricket", "metro by t-mobile": "metropcs",
    "u.s. cellular": "uscellular", "us cellular": "uscellular",
    "vodafone": "vodafone", "tim": "tim", "telecom italia": "tim",
    "wind": "wind", "orange": "orange",
}


def normalize_carrier(name: str) -> str:
    """Normalize a carrier name (human or key) to a gateway key."""
    key = (name or "").strip().lower()
    return _CARRIER_ALIASES.get(key, key)


def carrier_from_phone(phone: str) -> Optional[str]:
    """Best-effort carrier detection for a phone number.

    Uses the phonenumbers metadata (offline, no API) when available;
    returns a normalized gateway key or None when undetermined.
    """
    try:
        import phonenumbers
        from phonenumbers import carrier as _carrier
        parsed = phonenumbers.parse(phone, None)
        name = _carrier.name_for_number(parsed, "en") or ""
        if name:
            return normalize_carrier(name)
    except Exception:
        pass
    return None


def carrier_sms_address(phone: str, carrier: str) -> Optional[str]:
    """Map a phone to the email address that reaches its SMS inbox."""
    gateway = CARRIER_GATEWAYS.get(normalize_carrier(carrier))
    if not gateway:
        return None
    digits = "".join(c for c in phone if c.isdigit())
    if not digits:
        return None
    return f"{digits}{gateway}"
