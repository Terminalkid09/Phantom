import argparse
import os
import sys

from phantom.core.shell import PhantomShell
from rich.console import Console

console = Console()

def main():
    parser = argparse.ArgumentParser(description="Phantom offensive Security Framework")
    parser.add_argument("--profile", help="Load engagement profile at startup")
    parser.add_argument("--c2", action="store_true", help="Launch Phantom C2 interface instead of pentest shell")
    parser.add_argument("--auto", nargs="*", metavar="TARGET", default=None,
                        help="AUTO-MODE: with target(s) run the full kill chain "
                             "directly; with no target open the interactive "
                             "AUTO-MODE shell (same as `phantom.auto`)")
    # auto-mode passthrough flags (only meaningful with --auto <target>)
    parser.add_argument("--stealth", action="store_true", help="paranoid OPSEC (auto-mode)")
    parser.add_argument("--aggressive", action="store_true", help="loud, fast exploitation (auto-mode)")
    parser.add_argument("--speed", action="store_true", help="exploit first viable opening (auto-mode)")
    parser.add_argument("--plan", action="store_true", help="dry-run: show plan, execute nothing (auto-mode)")
    parser.add_argument("--verbose", action="store_true", help="stream live reasoning trace (auto-mode)")
    parser.add_argument("-a", "--agents", nargs="?", const=0, type=int, default=0,
                        metavar="N", help="sub-agent count: -a (auto) or -a2 (auto-mode)")
    parser.add_argument("--goal", default="deliver", help="terminal goal (auto-mode, default: deliver)")
    parser.add_argument("--profile-auto", dest="profile_auto", default="enterprise",
                        help="target profile (auto-mode, default: enterprise)")
    parser.add_argument("--resume", default="", metavar="CHECKPOINT",
                        help="resume from an auto-mode checkpoint (auto-mode)")
    parser.add_argument("--llm", action="store_true", help="optional local-LLM advisor (auto-mode)")
    parser.add_argument("--experience", action="store_true",
                        help="CROSS-ENGAGEMENT learning memory (auto-mode): "
                             "keep cause->repair experience between runs "
                             "(default: learning is scoped to this run only)")
    parser.add_argument("--evolution", action="store_true",
                        help="SELF-IMPROVEMENT (auto-mode): stable uncovered "
                             "failure patterns spawn a background sub-agent "
                             "that authors a new capability and opens a "
                             "reviewable PR (lab required; max 2 PRs/day)")
    parser.add_argument("--beta", action="store_true",
                        help="BETA CAPABILITIES (auto-mode): fetch open "
                             "auto-evolution PRs, gate them locally and use "
                             "the ones that pass (same full gate, lab "
                             "included; working tree untouched)")
    parser.add_argument("-y", "--yes", action="store_true", help="Run mode sequences without confirmation prompts")
    parser.add_argument("--setup", nargs="?", const="", metavar="TARGET",
                        help="guided setup: 'wsl' for the Windows WSL toolbox "
                             "flow, none for the full wizard (tools, doctor)")
    parser.add_argument("--doctor", action="store_true",
                        help="diagnostics only: python, tools, docker, WSL, "
                             "LLM transport — installs nothing")
    args, extra = parser.parse_known_args()

    if args.doctor:
        from phantom.utils.setup_wizard import doctor
        doctor()
        return
    if args.setup is not None:
        from phantom.utils.setup_wizard import run_wizard
        sys.exit(run_wizard(args.setup, assume_yes=args.yes))

    # Direct entry points: `phantom.c2` / `phantom.auto` land in the right
    # shell immediately (no flag), matching the `phantom` default.
    argv0 = os.path.basename(sys.argv[0] or "").lower()
    if argv0.startswith("phantom.c2") or (argv0 == "phantom-c2"):
        from phantom.core.c2_shell import run_c2
        run_c2()
        return
    if argv0.startswith("phantom.auto") or (argv0 == "phantom-auto"):
        from phantom.core.auto_shell import run_auto_shell
        run_auto_shell()
        return

    if args.c2:
        from phantom.core.c2_shell import run_c2
        run_c2()
        return

    if args.auto is not None:
        # `phantom --auto` (no target) -> interactive AUTO-MODE shell;
        # `phantom --auto <t1[,t2]...> [flags]` -> run the kill chain now.
        targets = [t for t in (args.auto + extra) if t.strip()]
        if not targets:
            from phantom.core.auto_shell import run_auto_shell
            run_auto_shell()
            return
        from phantom.core.automode import run_auto_mode
        run_auto_mode(
            targets=targets,
            aggressive=args.aggressive,
            stealth=args.stealth,
            speed=args.speed,
            plan=args.plan,
            verbose=args.verbose,
            agents=args.agents or 0,
            goal=args.goal,
            profile=args.profile_auto,
            llm=args.llm,
            experience=args.experience,
            evolution=args.evolution,
            beta=args.beta,
            resume=args.resume,
        )
        return

    shell = PhantomShell()
    shell.auto_run = args.yes
    if args.profile:
        shell.load_profile(args.profile)

    # Auto-session: register this open, offer to resume the last engagement
    from phantom.utils.auto_session import auto_export, offer_resume, register_open
    register_open()
    offer_resume(quiet=args.yes)

    try:
        shell.cmdloop()
    except KeyboardInterrupt:
        console.print("\n[dim]Phantom closed.[/]\n")
        return
    finally:
        # Auto-session: persist the engagement as an encrypted .pm on EVERY
        # close path (exit, quit, double Ctrl+C) without asking.
        exported = auto_export()
        if exported:
            console.print(f"[dim]Session auto-saved: {exported}[/]")

if __name__ == "__main__":
    main()