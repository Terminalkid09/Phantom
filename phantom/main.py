from phantom.core.shell import PhantomShell
from rich.console import Console

console = Console()

def main():
    shell = PhantomShell()
    try:
        shell.cmdloop()
    except KeyboardInterrupt:
        console.print("\n[dim]Phantom closed.[/]\n")
        return

if __name__ == "__main__":
    main()