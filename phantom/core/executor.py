import re
import subprocess
import threading
import sys
import shutil
from rich.console import Console
from phantom.core.session import session
from phantom.core.scope import is_in_scope

console = Console()

TIMEOUT_SECONDS = 300  # Ask user after this many seconds


def _is_safe_target(target: str) -> bool:
    return bool(re.match(r'^[a-zA-Z0-9.\-/:]+$', target))


def _is_tool_installed(cmd: str) -> bool:
    """Check if the primary tool in the command string is installed."""
    # Get the first word (the binary)
    tool = cmd.split()[0] if cmd.split() else ""
    if not tool:
        return True # Empty command, let subprocess handle it
    
    # Check if it exists in PATH
    return shutil.which(tool) is not None


def run_command(cmd: str, target_ip: str = "") -> str:
    """
    Run a shell command with interactive timeout.
    - Checks scope before running.
    - Checks for dangerous characters in target.
    - Checks if tool is installed.
    - Streams output in real time.
    - After TIMEOUT_SECONDS asks user: continue / skip / kill.
    Returns combined stdout+stderr as string.
    """
    if target_ip and session.scope and not is_in_scope(target_ip, session.scope):
        console.print(f"[red][!] Command blocked: {target_ip} is out of scope.[/]")
        return ""

    if target_ip and not _is_safe_target(target_ip):
        console.print(f"[red][!] Blocked: target '{target_ip}' contains dangerous characters.[/]")
        return ""

    # Check if the tool is installed
    if not _is_tool_installed(cmd):
        tool = cmd.split()[0] if cmd.split() else "Unknown"
        console.print(f"[yellow][!] Warning: tool '{tool}' is not installed. Skipping command.[/]")
        console.print(f"    [dim]Tip: Install it via 'sudo apt install {tool}' or equivalent.[/]")
        return ""

    console.print(f"\n  [dim]$ {cmd}[/]")
    session.add_history(cmd)

    output_lines = []

    try:
        process = subprocess.Popen(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

        while True:
            # Try to read output for TIMEOUT_SECONDS
            lines_in_window = []
            timed_out = False

            def _read():
                for line in process.stdout:
                    lines_in_window.append(line)

            reader = threading.Thread(target=_read, daemon=True)
            reader.start()
            reader.join(timeout=TIMEOUT_SECONDS)

            # Print whatever we got
            for line in lines_in_window:
                sys.stdout.write(line)
                sys.stdout.flush()
                output_lines.append(line)

            if not reader.is_alive():
                # Reader finished — process ended normally
                break

            # Reader still alive = process still running after TIMEOUT_SECONDS
            if process.poll() is None:
                console.print(
                    f"\n[yellow][!] Command still running after {TIMEOUT_SECONDS}s.[/]\n"
                    "    [y] Wait another 300s  "
                    "[n] Skip to next command  "
                    "[k] Kill and skip"
                )
                try:
                    choice = input("    Choice [y/n/k]: ").strip().lower() or "y"
                except (EOFError, KeyboardInterrupt):
                    choice = "k"

                if choice == "y":
                    # Continue — loop again with another TIMEOUT_SECONDS window
                    continue
                elif choice in ("n", "k"):
                    if choice == "k":
                        process.kill()
                    else:
                        # 'n' = skip but don't kill (let it run detached)
                        # In practice kill is safer
                        process.kill()
                    console.print("[yellow]  Command skipped.[/]")
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

    return "".join(output_lines)


def run_commands(commands: list, target_ip: str = "") -> dict:
    """
    Run a list of commands sequentially.
    Returns dict {command: output}.
    """
    results = {}
    for cmd in commands:
        # Strip AGGRESSIVE marker before running
        clean_cmd = cmd.replace(" AGGRESSIVE", "").strip()
        results[clean_cmd] = run_command(clean_cmd, target_ip)
    return results