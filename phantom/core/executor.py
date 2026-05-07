import re
import subprocess
import threading
import sys
import shutil
import os
from rich.console import Console
from phantom.core.session import session
from phantom.core.scope import is_in_scope

console = Console()

TIMEOUT_SECONDS = 300

# termios only on Unix/Linux/Mac
_IS_UNIX = os.name == "posix"
if _IS_UNIX:
    import termios


def _is_safe_target(target: str) -> bool:
    return bool(re.match(r'^[a-zA-Z0-9.\-/:]+$', target))


def _is_tool_installed(cmd: str) -> bool:
    """Check if the primary tool in the command string is installed."""
    tool = cmd.split()[0] if cmd.split() else ""
    if not tool:
        return True
    return shutil.which(tool) is not None


def _save_terminal():
    """Save current terminal settings (Unix only)."""
    if _IS_UNIX:
        try:
            return termios.tcgetattr(sys.stdin.fileno())
        except Exception:
            return None
    return None


def _restore_terminal(settings) -> None:
    """Restore terminal settings (Unix only)."""
    if _IS_UNIX and settings is not None:
        try:
            termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, settings)
        except Exception:
            pass


def _safe_input(prompt: str, default: str = "y") -> str:
    """
    Read user input safely after restoring terminal settings.
    Falls back to default on EOF or KeyboardInterrupt.
    """
    try:
        return input(prompt).strip().lower() or default
    except (EOFError, KeyboardInterrupt):
        return "k"


def run_command(cmd: str, target_ip: str = "") -> str:
    """
    Run a shell command with interactive timeout.

    Behavior:
    - Checks scope, safe target, tool installed.
    - Streams output in real time.
    - Saves and restores terminal settings (fixes invisible input bug).
    - After TIMEOUT_SECONDS asks user:
        y = wait another 300s
        n = send to background, buffer output, show at end of all commands
        k = kill definitively
    Returns combined stdout+stderr as string.
    """
    if target_ip and session.scope and not is_in_scope(target_ip, session.scope):
        console.print(f"[red][!] Command blocked: {target_ip} is out of scope.[/]")
        return ""

    if target_ip and not _is_safe_target(target_ip):
        console.print(f"[red][!] Blocked: target '{target_ip}' contains dangerous characters.[/]")
        return ""

    if not _is_tool_installed(cmd):
        tool = cmd.split()[0] if cmd.split() else "Unknown"
        console.print(f"[yellow][!] Tool '{tool}' not installed. Skipping.[/]")
        console.print(f"    [dim]Install with: sudo apt install {tool}[/]")
        return ""

    console.print(f"\n  [dim]$ {cmd}[/]")
    session.add_history(cmd)

    output_lines = []
    terminal_settings = _save_terminal()

    try:
        process = subprocess.Popen(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,  # Prevents child from stealing stdin from parent
            text=True,
            bufsize=1,
        )

        while True:
            lines_in_window = []

            def _read():
                for line in process.stdout:
                    lines_in_window.append(line)

            reader = threading.Thread(target=_read, daemon=True)
            reader.start()
            reader.join(timeout=TIMEOUT_SECONDS)

            # Print whatever arrived in this window
            for line in lines_in_window:
                sys.stdout.write(line)
                sys.stdout.flush()
                output_lines.append(line)

            if not reader.is_alive():
                # Reader finished — process ended normally
                break

            if process.poll() is None:
                # Process still running — restore terminal before asking
                _restore_terminal(terminal_settings)

                console.print(
                    f"\n[yellow][!] Command still running after {TIMEOUT_SECONDS}s.[/]\n"
                    "    [y] Wait another 300s  "
                    "[n] Send to background (output shown at end)  "
                    "[k] Kill and skip"
                )
                choice = _safe_input("    Choice [y/n/k]: ", default="y")

                if choice == "y":
                    continue

                elif choice == "n":
                    # Buffer remaining output in background thread
                    background_buffer = []
                    console.print("[yellow]  Running in background. Output will appear at end.[/]")

                    def _collect():
                        for line in process.stdout:
                            background_buffer.append(line)

                    bg_thread = threading.Thread(target=_collect, daemon=True)
                    bg_thread.start()

                    # Store in session for run_commands to display later
                    bg_key = f"_bg_{cmd[:40]}"
                    session.add_result(bg_key, {
                        "cmd": cmd,
                        "thread": bg_thread,
                        "buffer": background_buffer,
                    })
                    break

                elif choice == "k":
                    process.kill()
                    console.print("[yellow]  Command killed.[/]")
                    break
            else:
                break

        process.wait()

    except KeyboardInterrupt:
        try:
            process.kill()
        except Exception:
            pass
        console.print("\n[yellow][!] Interrupted by user (Ctrl+C). Moving to next command.[/]")

    except Exception as e:
        console.print(f"[red][!] Execution error: {e}[/]")

    finally:
        # Always restore terminal — fixes invisible input after sudo commands
        _restore_terminal(terminal_settings)

    return "".join(output_lines)


def run_commands(commands: list, target_ip: str = "") -> dict:
    """
    Run a list of commands sequentially.
    After all commands complete, shows buffered output
    from any commands sent to background with 'n'.
    Returns dict {command: output}.
    """
    results = {}
    for cmd in commands:
        clean_cmd = cmd.replace(" AGGRESSIVE", "").strip()
        results[clean_cmd] = run_command(clean_cmd, target_ip)

    # Show background command output at the end
    bg_keys = [k for k in session.results.keys() if k.startswith("_bg_")]
    if bg_keys:
        console.print("\n[bold cyan]── BACKGROUND OUTPUT ───────────────────────────────[/]")
        for key in bg_keys:
            data = session.results[key]
            cmd_label = data.get("cmd", key)
            buffer = data.get("buffer", [])
            thread = data.get("thread")

            # Wait max 5s for thread to finish collecting
            if thread and thread.is_alive():
                thread.join(timeout=5)

            terminal_settings = _save_terminal()
            _restore_terminal(terminal_settings)

            choice = _safe_input(
                f"\n  Finished: [dim]{cmd_label[:60]}[/]\n"
                f"  Show output now? [y/N]: ",
                default="n"
            )

            if choice == "y" and buffer:
                console.print()
                for line in buffer:
                    sys.stdout.write(line)
                sys.stdout.flush()
            elif not buffer:
                console.print(f"  [dim]No output captured.[/]")

            # Remove from session after showing
            del session.results[key]

    return results