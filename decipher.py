#!/usr/bin/env python

# uso: decipher.py
#
# Decipher messages (RSA)
#
# positional arguments:
#   --public-key                    Public RSA key
#   --private-key                   Private RSA key
#
# optional arguments:
#   -p                              Private RSA key password
#
# pylint: disable=deprecated-module, unused-variable, missing-module-docstring, broad-exception-caught, too-many-locals
#

import sys
import optparse

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives import serialization


def read_file(filename):
    """Read a file.

    Arguments:
    filename -- file name
    """

    with open(filename, 'rb') as file:
        return file.read()


def decrypt_aes(encrypted_aes_key, private_key):
    """Decipher AES key utilising private RSA key.

    Arguments:
    encrypted_aes_key -- encrypted AES key
    private_key -- private RSA key
    """
    plaintext = private_key.decrypt(
        encrypted_aes_key,
        asymmetric_padding.OAEP(
            mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext


def decrypt_ciphertext(ciphertext, aes_key, iv_vector):
    """Decipher encrypted message using AES key and IV vector.

    ciphertext -- ciphered text
    aes_key -- AES key
    iv -- IV vector
    """
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv_vector))
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext


def verify_signature(message, signature, public_key):
    """Verify the signature of the message using a public key.

    message -- the message
    signature -- the signature
    public_key -- public RSA key
    """
    public_key.verify(
        signature,
        message,
        asymmetric_padding.PSS(
            mgf=asymmetric_padding.MGF1(hashes.SHA256()),
            salt_length=asymmetric_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


def main():
    """Decipher a message with an RSA key"""

    parser = optparse.OptionParser("%prog --public-key <path> --private-key <path> -p [password]")
    parser.add_option('--public-key', dest='public_key', type='string')
    parser.add_option('--private-key', dest='private_key', type='string')
    parser.add_option("-p", dest='password', type="string")
    options, arguments = parser.parse_args()

    if not options.public_key:
        parser.error("You must provide a public key!")
        parser.print_usage()
        sys.exit()

    if not options.private_key:
        parser.error("You must provide a private key!")
        parser.print_usage()
        sys.exit()

    if not options.password:
        options.password = None
    else:
        options.password = options.password.encode()

    message_filename = "decipher/ciphertext.txt"
    signature_filename = "decipher/signature.sig"
    iv_filename = "decipher/IV.iv"
    encrypted_aes_key_filename = "decipher/aes_key.enc"
    alice_public_key_filename = options.public_key
    bob_private_key_filename = options.private_key

    # Read the files
    message = read_file(message_filename)
    signature = read_file(signature_filename)
    encrypted_aes_key = read_file(encrypted_aes_key_filename)
    iv_vector = read_file(iv_filename)

    # Load the public RSA key
    with open(alice_public_key_filename, "rb") as key_file:
        alice_public_key = serialization.load_pem_public_key(
            key_file.read()
        )

    # Load the private RSA key
    with open(bob_private_key_filename, "rb") as key_file:
        bob_private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=options.password
        )

    try:
        # Decipher the ciphered AES key with a private key
        aes_key = decrypt_aes(encrypted_aes_key, bob_private_key)

        # Decipher the ciphered text with the AES key
        plaintext = decrypt_ciphertext(message, aes_key, iv_vector)

        # Verify the message's signature
        verify_signature(plaintext, signature, alice_public_key)
        print("The signature is valid. The message is authentic.")
        print("Contents:")
        print(plaintext.decode())
    except Exception as exception:
        print("The signature is invalid. The message may not be authentic.")
        print("Error:", exception)


if __name__ == '__main__':
    main()
