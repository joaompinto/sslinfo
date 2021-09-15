import ssl
import socket
import sys
import OpenSSL.crypto as crypto
from datetime import datetime


def asn1time(time_str):
    time_obj = datetime.strptime(time_str.decode("ascii"), "%Y%m%d%H%M%SZ")
    return time_obj.strftime("%c")


def expires_in(time_until: str):
    time_from = datetime.now()
    time_until = datetime.strptime(time_until.decode("ascii"), "%Y%m%d%H%M%SZ")
    delta = (time_until - time_from).days + 1
    return delta


def get_certificate_san(x509cert):
    san = ""
    ext_count = x509cert.get_extension_count()
    for i in range(0, ext_count):
        ext = x509cert.get_extension(i)
        if "subjectAltName" in str(ext.get_short_name()):
            san = ext.__str__()
    return san


class SSLClient:
    def connect(self, hostname, port, timeout=10, skip_ssl_verification=False):
        ctx = ssl.create_default_context()
        if skip_ssl_verification:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            print(f"* Connecting to {hostname}, port {port}", file=sys.stderr)
            s.settimeout(timeout)
            s.connect((hostname, port))
            cert_bin = s.getpeercert(True)
            x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_bin)
            self.x509 = x509
            self.hostname = hostname
            self.port = port

    def x509dict(self, add_hints: bool):
        info_dict = {}
        x509 = self.x509

        components = []
        for component in x509.get_subject().get_components():
            key, value = component
            components.append(f"{key.decode()}={value.decode()}")
        info_dict["Hostname"] = self.hostname
        info_dict["Port"] = self.port
        info_dict["subject"] = "; ".join(components)
        info_dict["subjectAltName"] = get_certificate_san(x509)
        info_dict["SHA256"] = x509.digest("SHA256").decode()
        info_dict["Serial"] = x509.get_serial_number()

        components = []
        for component in x509.get_issuer().get_components():
            key, value = component
            components.append(f"{key.decode()}={value.decode()}")
        info_dict["issuer"] = "; ".join(components)

        info_dict["Valid from"] = asn1time(x509.get_notBefore())
        info_dict["Valid until"] = asn1time(x509.get_notAfter())

        expires_in_days = expires_in(x509.get_notAfter())
        if add_hints:
            if x509.has_expired():  # Yes, inverted logic for testing :)
                info_dict[
                    "Valid until"
                ] = f'[bold][red]{info_dict["Valid until"]} (expired !!!)[/red][/bold]'
            else:
                info_dict[
                    "Valid until"
                ] = f'{info_dict["Valid until"]} - expires in [green]{expires_in_days} day(s)[/green]'

        info_dict["SigAlgorithm"] = x509.get_signature_algorithm().decode()
        info_dict["Version"] = x509.get_version()
        return info_dict
