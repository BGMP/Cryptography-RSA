#!/usr/bin/env python

# uso: keygen.py
#
# Generate a pair of RSA keys
#
# pylint: disable=missing-module-docstring
#

import sys
import os
import getpass

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


DEFAULT_KEY_FILE = "id_rsa"
MAX_PASSPHRASE_ATTEMPTS = 5


def rsa_private_key(public_exponent=65537, key_size=2048):
    """Generate RSA private key.

    Arguments:
    public_exponent -- Mathematical property of the key's generation (default 65537)
    key_size -- Size of the key in bits (default 2048)
    """

    return rsa.generate_private_key(
        public_exponent=public_exponent,
        key_size=key_size,
    )


def main():
    """Main function.

    - Serialisation encoding: PEM
    - Private format: PKCS8
    - Password (optional): BestAvailableEncryption
    """

    print("Generating pair of public/private RSA keys.")
    key_file = input(f"Enter the file to which you would like to save the key "
                     f"({os.path.join(os.getcwd(), DEFAULT_KEY_FILE)}): ")
    if not key_file:
        key_file = DEFAULT_KEY_FILE

    passphrase = ""
    attempts = MAX_PASSPHRASE_ATTEMPTS
    while attempts:
        passphrase = getpass.getpass("Enter a password (nothing for no password): ")
        passphrase_confirm = getpass.getpass("Enter the password again: ")
        if passphrase == passphrase_confirm:
            break

        attempts -= 1
        if not attempts:
            print("Too many failed attempts. Try again.")
            sys.exit()

        print("Passwords don't match.")

    private_key = rsa_private_key()
    public_key = private_key.public_key()

    if passphrase:
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode())
        )
    else:
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

    with open(f"{key_file}.pem", "w", encoding="utf-8") as private_file:
        print(private_pem.decode(), file=private_file)

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open(f"{key_file}.pub", "w", encoding="utf-8") as public_file:
        print(public_pem.decode(), file=public_file)

    print("Successfully generated keys!")


if __name__ == '__main__':
    main()
