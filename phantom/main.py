import argparse
from phantom.core.shell import PhantomShell
from rich.console import Console

console = Console()

def main():
    parser = argparse.ArgumentParser(description="Phantom offensive Security Framework")
    parser.add_argument("--profile", help="Load engagement profile at startup")
    parser.add_argument("--c2", action="store_true", help="Launch Phantom C2 interface instead of pentest shell")
    args = parser.parse_args()

    if args.c2:
        from phantom.core.c2_shell import run_c2
        run_c2()
        return

    shell = PhantomShell()
    if args.profile:
        shell.load_profile(args.profile)
    try:
        shell.cmdloop()
    except KeyboardInterrupt:
        console.print("\n[dim]Phantom closed.[/]\n")
        return

if __name__ == "__main__":
    main()