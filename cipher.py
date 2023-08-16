#!/usr/bin/env python

# use: cipher.py
#
# Cipher messages (RSA)
#
# positional arguments:
#   --private-key                   Private RSA key
#   --public-key                    Public RSA key
#
# optional arguments:
#   -p                              Password for private RSA key
#
# pylint: disable=deprecated-module, unused-variable, missing-module-docstring
#

import sys
import os
import optparse

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding


def read_private_key(file, password=None):
    """Read a private key from a PEM file.

    Arguments:
    file -- private key file
    password -- password of the private key (default: None)
    """
    with open(file, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=password,
            backend=default_backend()
        )

    return private_key


def read_public_key(file):
    """Reads a public RSA key.

    Arguments:
    file -- public RSA key file
    """
    with open(file, 'rb') as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )

    return public_key


def encrypt_aes_key(aes_key, public_key):
    """Encrypts an AES key with a public RSA key.

    Arguments:
    aes_key -- AES key
    public_key -- public RSA key
    """
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return encrypted_key


def encrypt_text(text, key, iv_vector):
    """Encrypts plain text utilising an AES key and the IV vector in CBC mode.

    Arguments:
    text -- plain text
    key -- AES key
    iv_vector -- IV vector
    """
    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(text) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv_vector), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return ciphertext


def sign_text(text, private_key):
    """Signs the plain text utilising a private key

    Arguments:
    text -- plain text
    private_key -- private RSA key
    """
    signature = private_key.sign(
        text,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return signature


def main():
    """RSA Cipher
    """

    parser = optparse.OptionParser("%prog --private-key <path> --public-key <path> -p [password]")
    parser.add_option('--private-key', dest='private_key', type='string')
    parser.add_option('--public-key', dest='public_key', type='string')
    parser.add_option("-p", dest='password', type='string')
    options, arguments = parser.parse_args()

    if not options.private_key:
        parser.error("You must provide a private key!")
        parser.print_usage()
        sys.exit(0)

    if not options.public_key:
        parser.error("A public key must be provided!")
        parser.print_usage()
        sys.exit(0)

    if not options.password:
        options.password = None
    else:
        options.password = options.password.encode()

    plaintext = input("Enter a message to send: ").encode()
    private_key = read_private_key(options.private_key, options.password)
    public_key = read_public_key(options.public_key)

    signature = sign_text(plaintext, private_key)

    with open("cipher/signature.sig", "wb") as signature_file:
        signature_file.write(signature)

    # Generate AES key and IV vector
    aes_key = os.urandom(32)
    iv_vector = os.urandom(16)

    # Cipher plain text in CBC mode with AES
    ciphertext = encrypt_text(plaintext, aes_key, iv_vector)

    # Write ciphered text to a file
    with open('cipher/ciphertext.txt', 'wb') as ciphertext_file:
        ciphertext_file.write(ciphertext)

    # Write the IV vector to a file
    with open('cipher/IV.iv', 'wb') as iv_file:
        iv_file.write(iv_vector)

    # Cipher the AES key with the public key
    encrypted_key = encrypt_aes_key(aes_key, public_key)

    # Store the ciphered AES key
    with open('cipher/aes_key.enc', 'wb') as encrypted_key_file:
        encrypted_key_file.write(encrypted_key)

    print("Message successfully ciphered!")


if __name__ == '__main__':
    main()
