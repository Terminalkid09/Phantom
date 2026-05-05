import argparse
from phantom.core.shell import PhantomShell
from rich.console import Console

console = Console()

def main():
    parser = argparse.ArgumentParser(description="Phantom offensive Security Framework")
    parser.add_argument("--profile", help="Load engagement profile at startup")
    args = parser.parse_args()
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