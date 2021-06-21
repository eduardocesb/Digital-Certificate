from OpenSSL import crypto, SSL
import os
import base64
from socket import gethostname
from pprint import pprint
from time import gmtime, mktime

if not os.path.exists("output"):
    os.mkdir("output")

OUTPUT_CERT_FILE = "output/certificate.crt"
OUTPUT_PRIVATE_KEY_FILE = "output/private_key.pem"
OUTPUT_PUBLIC_KEY_FILE = "output/public_key.pem"
INPUT_FILE = "input/file.txt"
OUTPUT_SIGNATURE_FILE = "output/signature"

def create_self_signed_cert():

    # create a key pair
    key_size = int(input("Write the number of bits of the key (min 512): "))

    privateKey = crypto.PKey()
    privateKey.generate_key(crypto.TYPE_RSA, key_size)

    # create a self-signed cert
    certificate = crypto.X509()
    certificate.get_subject().C = input("Country Name (2 letter code) [e.g. BR]: ")
    certificate.get_subject().ST = input("State or Province Name (full name) [e.g. Piaui]: ")
    certificate.get_subject().L = input("Locality Name (eg, city) [e.g. Teresina]: ")
    certificate.get_subject().O = input("Organization Name (eg, company) [e.g. UFPI]: ")
    certificate.get_subject().OU = input("Organizational Unit Name (eg, section) [e.g Computer Science]: ")
    certificate.get_subject().CN = gethostname()
    certificate.get_subject().emailAddress = input("Email Address [ccn@ufpi.edu.br]: ")
    certificate.set_serial_number(int(input("Serial Number [e.g. 2104]: ")))
    certificate.gmtime_adj_notBefore(int(input("Start after (in seconds) [e.g. 10]: ")))
    certificate.gmtime_adj_notAfter(int(input("Expire after (in seconds) [e.g. 86400]: ")))
    certificate.set_issuer(certificate.get_subject())
    certificate.set_pubkey(privateKey)
    certificate.sign(privateKey, 'sha256')

    open(OUTPUT_CERT_FILE, "wb").write(crypto.dump_certificate(crypto.FILETYPE_PEM, certificate))
    open(OUTPUT_PRIVATE_KEY_FILE, "wb").write(crypto.dump_privatekey(crypto.FILETYPE_PEM, privateKey))
    open(OUTPUT_PUBLIC_KEY_FILE, "wb").write(crypto.dump_publickey(crypto.FILETYPE_PEM, privateKey))
    print("Keys and certificate saved successfuly!")

def check_signature():
    certificate = crypto.load_certificate(crypto.FILETYPE_PEM, open(OUTPUT_CERT_FILE, "rb").read())
    signature = open(OUTPUT_SIGNATURE_FILE, "rb").read()
    data = open(INPUT_FILE, "rb").read()

    try:
        crypto.verify(certificate, signature, data, 'sha256')
        return True
    except:
        return False 


def check_expired_certificate():
    certificate = crypto.load_certificate(crypto.FILETYPE_PEM, open(OUTPUT_CERT_FILE, "rb").read())
    return certificate.has_expired()


def sign_file():
    data = open(INPUT_FILE, "rb").read()
    private_key = crypto.load_privatekey(crypto.FILETYPE_PEM, open(OUTPUT_PRIVATE_KEY_FILE, "rb").read())
    signature = crypto.sign(private_key, data, 'sha256')
    open(OUTPUT_SIGNATURE_FILE, "wb").write(signature)
    print("File signed successfuly!")


if __name__ == "__main__":

    while(True):
        print("0 - Exit")
        print("1 - Generate certificate and keys")
        print("2 - Sign file and save signature")
        print("3 - Check signature")
        print("4 - Check if certificate is expired")

        option = input("\nChoose an option: ")

        if(option == "0"):
            exit()
        elif(option == "1"):
            create_self_signed_cert()
        elif(option == "2"):
            sign_file()
        elif(option == "3"):
            print("Valid signature: ", check_signature())
        elif(option == "4"):
            print("Certificate is expired: ", check_expired_certificate())