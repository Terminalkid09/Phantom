"""No third-party repository "we took an idea from" may become a dependency.

Phantom is MIT (see `LICENSE`). Linking a GPL-2.0 (stegseek), a GPL-3.0
(Osintgram) or an UNLICENSED (WhatsApp-OSINT) body of code into it would
relicense the project, and a line in `requirements.txt` is a link in every
sense that matters: the code ships inside the operator's working copy and in
every build produced from it, under Phantom's name.

What Phantom takes from upstream projects is IDEAS, re-implemented here in our
own code: the camouflage that keeps automated traffic from looking automated,
the social-engineering technique, the delivery trick. None of that needs the
upstream source, and none of it may drag the upstream licence in. The rule
below is therefore a LICENCE rule, not a style rule, and it is enforced rather
than documented: if a future change wants one of these in-process, it has to
change this list on purpose, in a commit a reviewer can see.
"""
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
MANIFESTS = ("requirements.txt", "requirements-dev.txt", "setup.py")


class Repo:
    def __init__(self, slug: str, license: str, note: str) -> None:
        self.slug = slug
        self.license = license
        self.note = note

    @property
    def name(self) -> str:
        return self.slug.split("/")[1]

    @property
    def module(self) -> str:
        """What a vendored copy would be imported as."""
        return self.name.lower().replace("-", "_")


REPOS = (
    Repo("apache/caldera", "Apache-2.0",
         "absorbable in licence terms only — the ideas are re-implemented, "
         "nothing is vendored"),
    Repo("RickdeJager/stegseek", "GPL-2.0",
         "an external process at most, never linked"),
    Repo("Datalux/Osintgram", "GPL-3.0",
         "the technique is re-implemented on our own client, the code is not"),
    Repo("kinghacker0/WhatsApp-OSINT", "no LICENSE file",
         "unlicensed code has no terms we can accept"),
)

# Every spelling a manifest or an import could carry. Note the deliberate
# absence of a bare "whatsapp" token: Phantom has its own WhatsApp delivery
# surface, and banning a word it legitimately uses would make this test noise.
_TOKENS = {
    "apache/caldera": ("apache/caldera", "caldera"),
    "RickdeJager/stegseek": ("rickdejager/stegseek", "stegseek"),
    "Datalux/Osintgram": ("datalux/osintgram", "osintgram"),
    "kinghacker0/WhatsApp-OSINT": ("kinghacker0/whatsapp-osint",
                                   "whatsapp-osint", "whatsapp_osint"),
}


def test_the_project_is_mit_so_the_constraint_is_real():
    text = (ROOT / "LICENSE").read_text(encoding="utf-8")
    assert text.startswith("MIT License")
    assert "GNU General Public License" not in text


def test_no_dependency_manifest_names_one_of_them():
    for manifest in MANIFESTS:
        text = (ROOT / manifest).read_text(encoding="utf-8").lower()
        for repo in REPOS:
            for token in _TOKENS[repo.slug]:
                assert token not in text, (
                    f"{manifest} names {token!r}, but {repo.slug} is "
                    f"{repo.license} ({repo.note}) and cannot become a "
                    f"dependency of an MIT project — re-implement the idea "
                    f"instead of linking the code")


def test_phantom_never_imports_them():
    scanned = 0
    offenders = []
    for path in (ROOT / "phantom").rglob("*.py"):
        scanned += 1
        text = path.read_text(encoding="utf-8", errors="replace")
        for repo in REPOS:
            if re.search(rf"^\s*(?:import|from)\s+{repo.module}\b", text,
                         re.M):
                offenders.append(f"{path.relative_to(ROOT)}: {repo.module}")
    # positive control: a scan that read nothing would pass by accident
    assert scanned > 100, scanned
    assert not offenders, offenders


def test_the_beacon_sources_do_not_vendor_them_either():
    offenders = []
    for path in (ROOT / "phantom" / "payloads").rglob("*"):
        if not path.is_file() or path.suffix not in (".h", ".hpp", ".cpp",
                                                     ".c", ".py"):
            continue
        text = path.read_text(encoding="utf-8", errors="replace").lower()
        for repo in REPOS:
            for token in _TOKENS[repo.slug]:
                if token in text:
                    offenders.append(f"{path.relative_to(ROOT)}: {token}")
    assert not offenders, offenders


def test_no_vendored_copy_lives_in_the_tree():
    for repo in REPOS:
        assert not (ROOT / "phantom" / "vendor" / repo.name.lower()).exists()
        assert not (ROOT / "vendor" / repo.name.lower()).exists()
