import argparse
import ssl
import socket
import sys
from pprint import pprint
from urllib.parse import urlparse


class CommandArgs:
    def __init__(self):
        parser = argparse.ArgumentParser(description="Process some integers.")
        parser.add_argument("--verbose", help="Set verbose mode", action="store_true")
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
        self.parser = parser

    def parse(self):
        self.args = self.parser.parse_args()

    def run(self):
        hostname = self.args.hostname
        if "//" in hostname:
            url_parts = urlparse(hostname)
            hostname = url_parts.netloc
        if ":" in hostname:
            hostname, port = hostname.split(":")

        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            if self.args.verbose:
                print(
                    f"* Connecting to {hostname}, port {self.args.port}",
                    file=sys.stderr,
                )
            s.settimeout(self.args.timeout)
            s.connect((hostname, self.args.port))
            cert = s.getpeercert()
        pprint(cert)
