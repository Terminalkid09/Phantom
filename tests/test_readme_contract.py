"""The README must not invent flags, and must not hide them either.

The audit found the root README claiming two flags that never existed
(`--no-stealth`, `--agent`) and a test count stale by 5x, while fourteen real
flags lived only in prose. Worse, `--agent` was SWALLOWED: `parse_known_args`
puts unknown options in `extra`, where nothing looked at them, so an operator
could pass a flag that did nothing and read a clean run.

This is the source-scanning contract the same audit asked for (the repo already
does it for the Electron allowlist): the flags the README documents must exist
in `phantom/main.py`, every flag in the parser must be documented, and the
COUNTED claims (test files, API routes) must match reality.
"""
import os
import pathlib
import re
import unittest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_README = _ROOT / "README.md"


def _read(path: pathlib.Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _readme() -> str:
    return _read(_README)


def _readme_cli_flags(text: str = "") -> set:
    """Flags from the CLI's OWN documentation, not from every tool it mentions.

    The README also quotes apt/npm/tsc and the C2 shell's own commands
    (`ad add-user --kerberoastable`, `nmap --script`, `tsc --noEmit`), and
    checking THOSE against `main.py` would be nonsense. So the scope is:

    * lines inside fenced blocks that START with the `phantom` entry point;
    * rows of the flag-reference table (``| `--flag` | … |``).
    """
    text = text or _readme()
    in_block = False
    scope: list = []
    for line in text.splitlines():
        if line.strip().startswith("```"):
            in_block = not in_block
            continue
        if in_block and re.match(r"\s*phantom[.\s]", line):
            scope.append(line)
        if line.startswith("| `--") or line.startswith("| `-"):
            scope.append(line)
    return set(re.findall(r"(?<![\w-])(--[a-zA-Z][\w-]*)", "\n".join(scope)))


def _parser_actions():
    from phantom.main import build_parser
    return build_parser()._actions


def _parser_flags() -> set:
    out = set()
    for action in _parser_actions():
        out.update(action.option_strings)
    return out


class TestNoInventedFlags(unittest.TestCase):
    def test_every_flag_the_readme_names_exists(self):
        unknown = sorted(_readme_cli_flags() - _parser_flags())
        self.assertEqual(unknown, [],
                         "the README documents flags this entry point does "
                         "not accept — an operator following it gets an error "
                         "at best, a silently ignored option at worst")

    def test_the_two_flags_the_audit_found_are_gone(self):
        text = _readme()
        self.assertNotIn("--no-stealth", text)
        self.assertNotIn("--agent ", text.replace("--agents ", ""))

    def test_the_readme_does_not_claim_the_manual_shell_is_the_default(self):
        for line in _readme().splitlines():
            if line.startswith("phantom ") and "#" in line:
                comment = line.split("#", 1)[1].lower()
                self.assertNotIn("manual core shell", comment, line)


class TestNoUndocumentedFlags(unittest.TestCase):
    def test_every_parser_flag_is_documented(self):
        text = _readme()
        missing = []
        for action in _parser_actions():
            names = [o for o in action.option_strings
                     if o not in ("-h", "--help")]
            if not names:
                continue
            if not any(re.search(rf"(?<![\w-]){re.escape(name)}(?![\w-])", text)
                       for name in names):
                missing.append(names[0])
        self.assertEqual(sorted(missing), [],
                         "these flags exist but the README never mentions "
                         "them; an operator cannot discover them from the docs")


class TestTheCountedClaimsAreReal(unittest.TestCase):
    """A number in the README is a claim, and this is how it stays true."""

    def test_code_blocks_and_paths_run_the_real_cli(self):
        """`phantom` in a code block must be the entry point that exists."""
        from phantom.main import build_parser
        self.assertIsNotNone(build_parser())

    def test_the_test_file_count_matches_the_tree(self):
        text = _readme()
        match = re.search(r"tests/\s*#\s*(\d+) test files", text)
        self.assertIsNotNone(match, "the project tree must state a test count")
        real = len(list((_ROOT / "tests").glob("test_*.py")))  # 374 at the
                                                              # time of writing
        self.assertEqual(int(match.group(1)), real,
                         "the README test count is stale")

    def test_the_api_route_count_matches_the_source(self):
        text = _readme()
        match = re.search(r"(\d+) route registrations", text)
        self.assertIsNotNone(match, "the README must state the route count")
        source = _read((_ROOT / "phantom" / "api" / "server.py"))
        real = len(re.findall(r"@routes\.", source))
        self.assertEqual(int(match.group(1)), real,
                         "the README API route count is stale")

    def test_the_project_tree_puts_run_c2_where_it_really_is(self):
        text = _readme()
        self.assertIn("├── _run_c2.py", text)
        self.assertTrue(os.path.exists(_ROOT / "_run_c2.py"))
        # and it is NOT inside the package (that is where the tree used to say)
        self.assertFalse(os.path.exists(_ROOT / "phantom" / "_run_c2.py"))


class TestTheDocsIndexStaysTrue(unittest.TestCase):
    """`docs/README.md` claims to index every document; nothing checked it.

    The audit praised the index (canonical vs historical, no unindexed file, no
    dangling row) — and then a benchmark page appeared in `docs/` that the index
    never mentioned, which is how that strength dies quietly. Both directions
    are contract-tested here, so adding a document means one row in the index.
    """

    def _index(self):
        return _read(_ROOT / "docs" / "README.md")

    def test_every_document_in_docs_is_indexed(self):
        index = self._index()
        missing = [p.name for p in sorted((_ROOT / "docs").glob("*.md"))
                   if p.name != "README.md" and p.name not in index]
        self.assertEqual(missing, [],
                         "documents nothing in docs/README.md points at: they "
                         "are exactly what a reader will never find")

    def test_every_row_points_at_a_document_that_exists(self):
        index = self._index()
        broken = [link for link in re.findall(r"\]\(([^)]+\.md)\)", index)
                  if not (_ROOT / "docs" / link).exists()
                  and not link.startswith("..")]
        self.assertEqual(broken, [],
                         "index rows pointing at a file that is not there")

    def test_the_historical_audits_declare_which_one_is_current(self):
        """Two audits on the same subject must not contradict each other in
        silence: the newer one says what it supersedes."""
        index = self._index()
        self.assertIn("superseded", index.lower())
        current = _read(_ROOT / "docs" / "Audit_2026-10-13.md")
        self.assertIn("ManusReview.md", current)
        older = _read(_ROOT / "docs" / "ManusReview.md")
        self.assertIn("Audit_2026-10-13.md", older)

    def test_the_master_review_is_labelled_as_instructions_not_findings(self):
        """`master_review.md` is a prompt for an external reviewer. The index
        used to call it "authoritative", which turned a prompt into a source."""
        index = self._index().lower()
        row = [line for line in index.splitlines() if "master_review.md" in line]
        self.assertTrue(row, "the master review must stay indexed")
        self.assertIn("instruction", row[0])
        body = _read(_ROOT / "docs" / "master_review.md")
        self.assertIn("ISTRUZIONI, non finding", body)


if __name__ == "__main__":
    unittest.main()
