from rich.console import Console
from rich.table import Table


def print_ssl_info(ssl_info):
    console = Console()

    table = Table(show_header=False)
    for key, value in ssl_info.items():
        table.add_row(key, str(value))
    console.print(table)
