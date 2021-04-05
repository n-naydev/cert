# A simple app to create x509 certificates

# Setup

```bash
virtualenv venv
. venv/bin/activate
pip install -r requirements.txt
```

# Usage

```
usage: cert.py [-h] [-cn CN] [-c C] [-l L] [-st ST] [-o O] [-ou OU] [-emailAddress EMAILADDRESS] [-serialNumber SERIALNUMBER] [-validityStartInSeconds VALIDITYSTARTINSECONDS]
               [-validityEndInSeconds VALIDITYENDINSECONDS] [-distinguishedName DISTINGUISHEDNAME] [-subjectAltName SUBJECTALTNAME] [-keyUsage KEYUSAGE] [-extendedKeyUsage EXTENDEDKEYUSAGE]
               [-cryptoType CRYPTOTYPE] [-bits BITS] [-digest DIGEST] [-key KEY] [-cert CERT]

optional arguments:
  -h, --help            show this help message and exit
  -cn CN                CN (Common Name)
  -c C                  C (Country Name)
  -l L                  L (Locality)
  -st ST                ST (State or Province)
  -o O                  O (Organization)
  -ou OU                OU (Organization Unit)
  -emailAddress EMAILADDRESS, -e EMAILADDRESS
                        emailAddres
  -serialNumber SERIALNUMBER, -sn SERIALNUMBER
                        serialNumber
  -validityStartInSeconds VALIDITYSTARTINSECONDS, -vs VALIDITYSTARTINSECONDS
                        validityStart in seconds
  -validityEndInSeconds VALIDITYENDINSECONDS, -ve VALIDITYENDINSECONDS
                        validityEnd in seconds
  -distinguishedName DISTINGUISHEDNAME, -dn DISTINGUISHEDNAME
                        DN (Distinguished Name)
  -subjectAltName SUBJECTALTNAME, -san SUBJECTALTNAME
                        SAN (Subject Alt Name)
  -keyUsage KEYUSAGE, -ku KEYUSAGE
                        KU (Key Usage)
  -extendedKeyUsage EXTENDEDKEYUSAGE, -eku EXTENDEDKEYUSAGE
                        EKU (Extended Key Usage)
  -cryptoType CRYPTOTYPE, -t CRYPTOTYPE
                        Crypto Type
  -bits BITS, -b BITS   Crypto number of bits
  -digest DIGEST, -dig DIGEST
                        Digest
  -key KEY, -key-file KEY
                        Key filename to be created
  -cert CERT, -cert-file CERT
                        Cert filename to be creted
```
