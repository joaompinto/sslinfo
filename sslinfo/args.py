import argparse
import json
from urllib.parse import urlparse

from .sslclient import SSLClient
from .view import print_ssl_info


class CommandArgs:
    def __init__(self):
        parser = argparse.ArgumentParser(description="Process some integers.")
        parser.add_argument(
            "-k", help="Do not validate certificate", action="store_true"
        )
        parser.add_argument("-v", help="Set verbose mode", action="store_true")
        parser.add_argument(
            "-f", help="Select field to print", nargs="+", type=str, action="append"
        )
        parser.add_argument("hostname", help="Connect to hostname", metavar="HOSTNAME")
        parser.add_argument(
            "--port", help="Using port", metavar="PORT", type=int, default=443
        )
        parser.add_argument(
            "--timeout",
            help="Max connection timeout (secs)",
            metavar="TIMEOUT",
            type=int,
            default=10,
        )
        parser.add_argument("-j", help="Produce json output", action="store_true")
        self.parser = parser

    def parse(self):
        self.args = self.parser.parse_args()

    def run(self):

        hostname = self.args.hostname
        port = self.args.port
        if "//" in hostname:
            url_parts = urlparse(hostname)
            hostname = url_parts.netloc
        if ":" in hostname:
            hostname, port = hostname.split(":")
            port = int(port)

        ssl_client = SSLClient()
        ssl_client.connect(hostname, port, self.args.timeout, self.args.k is True)
        x509dict = ssl_client.x509dict(add_hints=not self.args.j)
        if self.args.f:
            for key in self.args.f[0]:
                print(x509dict[key])
                return
        if self.args.j:
            print(json.dumps(x509dict, indent=4))
        else:
            print_ssl_info(x509dict)
