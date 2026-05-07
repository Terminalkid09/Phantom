from phantom.modules.base_module import BaseModule
from rich.console import Console

console = Console()

class ExampleModule(BaseModule):
    module_name = "example"

    def do_run(self, _):
        console.print("[green]Hello from the example plugin![/]")
        console.print("[dim]This shows that the plugin system works.[/]")

    def do_hello(self, _):
        console.print("[cyan]Hello, world![/]")