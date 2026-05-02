import subprocess
from rich.console import Console
from phantom.core.session import session
from phantom.core.scope import is_in_scope

console = Console()

def run_command(cmd: str, target_ip: str = "") -> str:
    """
    Run a shell command.
    If target_ip is provided, check it against the session scope before execution.
    Returns the combined stdout+stderr as a string.
    """
    if target_ip and session.scope and not is_in_scope(target_ip, session.scope):
        console.print(f"[red][!] Command blocked: {target_ip} is out of scope.[/]")
        return ""

    console.print(f"\n  [dim]$ {cmd}[/]")
    session.add_history(cmd)

    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=300,   # after the command will be terminated
        )
        output = result.stdout + result.stderr
        if output.strip():
            console.print(output)
        return output
    except subprocess.TimeoutExpired:
        console.print("[red][!] Timeout expired (300 seconds).[/]")
        return ""
    except Exception as e:
        console.print(f"[red][!] Execution error: {e}[/]")
        return ""

def run_commands(commands: list, target_ip: str = "") -> dict:
    """
    Run a list of commands sequentially.
    Returns a dictionary {command: output}.
    """
    results = {}
    for cmd in commands:
        results[cmd] = run_command(cmd, target_ip)
    return results