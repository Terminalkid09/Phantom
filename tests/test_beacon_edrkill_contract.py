"""C1 — `edr-kill` keeps the capability and loses the two defects around it.

The capability is legitimate (professional operators, authorized engagements,
signed off in the RoE). What was wrong is how it was written:

1. `kill_av()` called `disable_defender()` INSIDE the expression that built
   the report line:
       out << "defender_realtime=" << (disable_defender() ? ... )
   So FORMATTING the text wrote to the registry. Measuring and acting were the
   same statement, which means anything that only wanted to look switched
   Defender off.
2. The action was `system()`: `reg add` spawned cmd.exe + reg.exe twice per
   key, `sc stop` one `sc.exe` per service. Process creation is the loudest
   event an EDR and a SIEM both record, and it was coming from the module
   whose whole point is not being noticed.

`tests/test_edr_kill.py` (the operator-facing contract: aggressive-only,
detect-first, the interpreter) still passes unchanged — the capability is
still there. These tests pin the fix: detection is separable from action, the
action goes through advapi32, the report says what was done, and the
obfuscated literals are not read through a pointer into a wiped temporary.
"""
import os
import pathlib
import re
import shutil
import subprocess

import pytest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_SRC = _ROOT / "phantom" / "payloads" / "beacon" / "src"
_EVASION = _SRC / "evasion.h"


def _evasion() -> str:
    return _EVASION.read_text(encoding="utf-8", errors="replace")


def _fn(src: str, name: str) -> str:
    """The body of one C++ function, by brace balance.

    ``name`` must include the return type: a bare name also matches the
    comments that describe the function, and the slice would then start at
    whatever brace comes next.
    """
    start = src.index(name)
    start = src.index("{", start)
    depth = 0
    for i in range(start, len(src)):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                return src[start:i + 1]
    raise AssertionError(f"unbalanced braces after {name}")


class TestDetectingIsNotActing:
    def test_the_read_only_report_writes_and_stops_nothing(self):
        body = _fn(_evasion(), "std::string kill_av_report(std::vector")
        for forbidden in ("system(", "disable_defender", "RegSetValueEx",
                          "stop_service", "wevtutil"):
            assert forbidden not in body, (
                f"the read-only report must not {forbidden!r}: it is the "
                f"function the operator calls to LOOK at the host")

    def test_the_action_is_not_hidden_in_a_formatting_expression(self):
        # The exact shape of the bug: the registry write lived inside the
        # STATEMENT that built the report line, so `out << "..."
        # << (disable_defender() ? ...)` wrote when it formatted. Statements,
        # not lines: the call sat on a continuation line.
        for statement in re.findall(r"[^;{}]+;", _evasion()):
            if "out <<" in statement:
                assert "disable_defender" not in statement, statement.strip()

    def test_the_action_calls_the_report_instead_of_re_detecting(self):
        body = _fn(_evasion(), "std::string kill_av()")
        assert "kill_av_report(&services)" in body

    def test_the_action_says_what_it_did(self):
        body = _fn(_evasion(), "std::string kill_av()")
        assert "action_taken=edr-kill" in body
        # and the line the engagement report has to carry
        assert "kAuditLine()" in body
        assert "audit=operator disabled" in _evasion()

    def test_the_report_and_the_action_share_one_detection_pass(self):
        # `kill_av()` must not enumerate the host twice (each enumeration
        # spawns a hidden PowerShell on Windows)
        body = _fn(_evasion(), "std::string kill_av()")
        assert body.count("dfns::detect_defensive_services") == 0
        assert _fn(_evasion(), "std::string kill_av_report(std::vector").count(
            "dfns::detect_defensive_services") == 1


class TestTheActionDoesNotSpawnProcesses:
    def test_no_registry_write_goes_through_reg_exe(self):
        # the obfuscated literal is what reaches system(); the comments are
        # allowed to name the command they replaced.
        assert "XOR_STR(\"reg add" not in _evasion()

    def test_no_service_stop_goes_through_sc_exe(self):
        win = _fn(_evasion(), "std::string kill_av()")
        assert "XOR_STR(\"sc stop" not in _evasion()
        # the POSIX branch legitimately keeps systemctl/pkill (no in-process
        # API for unit control); the Windows branch must not shell out for it
        win_branch = win.split("#else")[0]
        assert "system(" not in win_branch.split("wevtutil")[0]

    def test_the_registry_write_uses_the_api(self):
        body = _fn(_evasion(), "DefenderPolicy disable_defender()")
        assert "RegSetValueEx" not in body       # resolved by hash, not named
        assert "FN_REGSETVALUEEXW" in body
        assert "FN_REGCREATEKEYEXW" in body
        assert "FN_REGCLOSEKEY" in body
        assert "ERROR_SUCCESS" in body

    def test_the_service_stop_uses_the_sc_manager(self):
        assert "struct ScmApi" in _evasion()
        body = _fn(_evasion(), "bool stop_service(")
        assert "SERVICE_CONTROL_STOP" in body
        assert "api.close(" in body              # both handles closed

    def test_only_the_log_clear_still_needs_a_child_process(self):
        win = _fn(_evasion(), "std::string kill_av()").split("#else")[0]
        assert win.count("system(") == 1
        # and the file says why it is still there
        assert "EvtClearLog" in _evasion()


class TestObfuscatedLiteralsAreNotDangling:
    """`XOR_DEC(...)` is a temporary that WIPES its buffer when destroyed: a
    `const char*` taken from it points at zeroed memory. The old
    `disable_defender()` built its command that way, so `system()` received an
    EMPTY command string and could only ever fail — which the report then
    blamed on Tamper Protection."""

    _PTR_DECL = re.compile(
        r"^\s*(const\s+)?(char|wchar_t)\s*\*+\s*\w+\s*=[^;]*XOR_DEC\([^;]*\.c_str\(\)")

    def test_no_source_file_stores_it_in_a_raw_pointer(self):
        offenders = []
        for path in sorted(_SRC.glob("*")):
            if path.suffix not in (".h", ".cpp", ".c"):
                continue
            for lineno, line in enumerate(
                    path.read_text(encoding="utf-8", errors="replace")
                    .splitlines(), 1):
                if self._PTR_DECL.search(line):
                    offenders.append(f"{path.name}:{lineno}: {line.strip()}")
        assert not offenders, "dangling obfuscated pointer:\n" + "\n".join(offenders)

    def test_the_registry_paths_are_std_strings(self):
        body = _fn(_evasion(), "DefenderPolicy disable_defender()")
        assert "const std::string paths[2]" in body
        assert "const std::string values[2]" in body


class TestEmbeddedHashesAreReal:
    """Every API is resolved by djb2 hash: a wrong constant is an API that
    never resolves, i.e. a capability that silently does nothing. The map is
    recomputed here from the symbol names the comments carry."""

    MODULES = {
        "HASH_KERNEL32": "kernel32.dll",
        "HASH_NTDLL": "ntdll.dll",
        "HASH_WINHTTP": "winhttp.dll",
        "HASH_ADVAPI32": "advapi32.dll",
    }
    FUNCTIONS = {
        "FN_LOADLIBRARYA": "LoadLibraryA",
        "FN_GETPROCADDRESS": "GetProcAddress",
        "FN_REGCREATEKEYEXW": "RegCreateKeyExW",
        "FN_REGSETVALUEEXW": "RegSetValueExW",
        "FN_REGCLOSEKEY": "RegCloseKey",
        "FN_OPENSCMANAGERA": "OpenSCManagerA",
        "FN_OPENSERVICEA": "OpenServiceA",
        "FN_CONTROLSERVICE": "ControlService",
        "FN_CLOSESERVICEHANDLE": "CloseServiceHandle",
    }

    @staticmethod
    def _djb2(text: str, *, lower: bool = False) -> int:
        if lower:
            text = text.lower()
        h = 7331
        for ch in text:
            h = ((h << 5) + h) + (ord(ch) & 0xFF)
            h &= 0xFFFFFFFF
        return h

    def _constant(self, name: str) -> int:
        match = re.search(rf"constexpr uint32_t {name}\s*=\s*0x([0-9A-Fa-f]+)",
                          _evasion())
        assert match, f"{name} is gone: was the API resolution replaced?"
        return int(match.group(1), 16)

    @pytest.mark.parametrize("name,symbol", sorted(MODULES.items()))
    def test_module_hashes(self, name, symbol):
        assert self._constant(name) == self._djb2(symbol, lower=True)

    @pytest.mark.parametrize("name,symbol", sorted(FUNCTIONS.items()))
    def test_function_hashes(self, name, symbol):
        assert self._constant(name) == self._djb2(symbol)


class TestTheWindowsBeaconStillCompiles:
    def test_minw_syntax_check_of_the_beacon(self):
        compiler = shutil.which("x86_64-w64-mingw32-g++")
        if compiler is None:
            pytest.skip("no MinGW-w64 compiler on this runner")
        argv = [compiler, "-std=c++20", "-fsyntax-only", "-Wall", "-Wextra",
                "-Werror", "-Wno-unknown-pragmas",
                "-Wno-missing-field-initializers", "-Wno-cast-function-type",
                f"-I{_SRC}", str(_SRC / "main.cpp")]
        build = subprocess.run(argv, capture_output=True, text=True,
                               timeout=900)
        assert build.returncode == 0, build.stdout + build.stderr
