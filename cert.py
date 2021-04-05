import argparse
import sys
from typing import Dict, List, Tuple

from OpenSSL import SSL, crypto
from OpenSSL.crypto import TYPE_DH, TYPE_DSA, TYPE_EC, TYPE_RSA


class Cert:
    """
    A class representing a certificate. It would be equivalent to the following command:
        $openssl req -x509 -out localhost.crt -keyout localhost.key \
            -newkey rsa:2048 -nodes -sha256 \
            -subj '/CN=localhost' -extensions EXT -config <( \
            printf "[dn]\nCN=localhost\n[req]\ndistinguished_name = dn\n[EXT]\nsubjectAltName=DNS:localhost\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth")
    """
    type_map: Dict = {
        "RSA": TYPE_RSA,
        "DSA": TYPE_DSA,
        "DH": TYPE_DH,
        "EC": TYPE_EC
    }
    def __init__(
        self,
        cn: str = "localhost",
        c: str = None,
        l: str = None,
        st: str = None,
        o: str = None,
        ou: str = None,
        emailAddress: str = None,
        serialNumber: str = 0,
        validityStartInSeconds: str = 0,
        validityEndInSeconds: str = 10*365*24*60*60,
        distinguishedName: str = "localhost",
        subjectAltName: str = "DNS:localhost",
        keyUsage: str = "digitalSignature",
        extendedKeyUsage: str = "serverAuth",
        cryptoType: str = "RSA",
        bits: str = 4096,
        digest: str = "sha512",
        **kwargs
    ) -> None:

        # create a key pair
        self.key = crypto.PKey()
        self.key.generate_key(self.type_map.get(cryptoType, TYPE_RSA), bits)
        # create the certificate
        self.cert = crypto.X509()
        subj = self.cert.get_subject()
        subj.CN = cn
        if c is not None:
            subj.C = c
        if st is not None:
            subj.ST = st
        if l is not None:
            subj.L = l
        if o is not None:
            subj.O = o
        if ou is not None:
            subj.OU = ou
        if emailAddress is not None:
            subj.emailAddress = emailAddress
        extensions = [
            crypto.X509Extension(b"subjectAltName", False, subjectAltName.encode()),
            crypto.X509Extension(b"keyUsage", False, keyUsage.encode()),
            crypto.X509Extension(b"extendedKeyUsage", False, extendedKeyUsage.encode())
        ]
        self.cert.add_extensions(extensions)
        self.cert.set_serial_number(serialNumber)
        self.cert.gmtime_adj_notBefore(0)
        self.cert.gmtime_adj_notAfter(validityEndInSeconds)
        self.cert.set_issuer(subj)
        self.cert.set_pubkey(self.key)
        self.cert.sign(self.key, digest)

    def save(
        self,
        key_file: str,
        cert_file: str
    ) -> None:
        """
        Method to save the certificate and key.
        Can be checked afterwards with:
            $openssl x509 -in selfsigned.crt -text
        """
        with open(cert_file, "w") as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, self.cert).decode("utf-8"))
        with open(key_file, "w") as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, self.key).decode("utf-8"))


class ArgParser(argparse.ArgumentParser):
    def __init__(self):
        super().__init__()
        self.add_argument("-cn", type=str, help="CN (Common Name)", default=argparse.SUPPRESS)
        self.add_argument("-c", type=str, help="C (Country Name)", default=argparse.SUPPRESS)
        self.add_argument("-l", type=str, help="L (Locality)", default=argparse.SUPPRESS)
        self.add_argument("-st", type=str, help="ST (State or Province)", default=argparse.SUPPRESS)
        self.add_argument("-o", type=str, help="O (Organization)", default=argparse.SUPPRESS)
        self.add_argument("-ou", type=str, help="OU (Organization Unit)", default=argparse.SUPPRESS)
        self.add_argument("-emailAddress", "-e", type=str, help="emailAddres", default=argparse.SUPPRESS)
        self.add_argument("-serialNumber", "-sn", type=int, help="serialNumber", default=argparse.SUPPRESS)
        self.add_argument("-validityStartInSeconds", "-vs", type=int, help="validityStart in seconds", default=argparse.SUPPRESS)
        self.add_argument("-validityEndInSeconds", "-ve", type=int, help="validityEnd in seconds", default=argparse.SUPPRESS)
        self.add_argument("-distinguishedName", "-dn", type=str, help="DN (Distinguished Name)", default=argparse.SUPPRESS)
        self.add_argument("-subjectAltName", "-san", type=str, help="SAN (Subject Alt Name)", default=argparse.SUPPRESS)
        self.add_argument("-keyUsage", "-ku", type=str, help="KU (Key Usage)", default=argparse.SUPPRESS)
        self.add_argument("-extendedKeyUsage", "-eku", type=str, help="EKU (Extended Key Usage)", default=argparse.SUPPRESS)
        self.add_argument("-cryptoType", "-t",type=str, help="Crypto Type", default=argparse.SUPPRESS)
        self.add_argument("-bits", "-b", type=int, help="Crypto number of bits", default=argparse.SUPPRESS)
        self.add_argument("-digest", "-dig", type=str, help="Digest", default=argparse.SUPPRESS)
        self.add_argument("-key", "-key-file", type=str, help="Key filename to be created", default="private.key")
        self.add_argument("-cert", "-cert-file", type=str, help="Cert filename to be creted", default="selfsigned.crt")
    
    def parse_args(self) -> argparse.Namespace:
        if len(sys.argv)==1:
            self.print_help(sys.stderr)
            sys.exit(1)
        return super().parse_args()


if __name__ == "__main__":
    parser = ArgParser()
    args = parser.parse_args()
    args_dict = vars(args)
    print("Create certificate with the following arguments:")
    for k, v in args_dict.items():
        print(f"{k} = {v}")
    cert = Cert(**args_dict)
    cert.save(args.key, args.cert)
