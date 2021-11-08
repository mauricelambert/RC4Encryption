#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This package implements RC4 encryption.
#    Copyright (C) 2021  Maurice Lambert

#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.

#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.

#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
###################

"""
This file implements RC4 cipher.

>>> rc4 = RC4Encryption(b'key')
>>> rc4.make_key()
>>> cipher = rc4.crypt(b'secrets')
>>> cipher_continuation = rc4.crypt(b'secrets')
>>> assert cipher_continuation != cipher
>>> rc4.reset(b'key')
>>> rc4.make_key()
>>> rc4.crypt(cipher)
b'secrets'
>>> rc4.crypt(cipher_continuation)
b'secrets'

~# python3 RC4Encryption.py -s secrets -6 key
eyA34C6Mtw==
~# python3 RC4Encryption.py -s eyA34C6Mtw== -n base64 key
secrets
~# python3 RC4Encryption.py -i secrets.file -6 -o cipher.b64 key
~# python3 RC4Encryption.py -o decipher.file -n base64 -i cipher.b64 key
"""

__version__ = "0.0.1"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """This package implements RC4 encryption."""
license = "GPL-3.0 License"
__url__ = "https://github.com/mauricelambert/RC4Encryption"

copyright = """
RC4Encryption  Copyright (C) 2021  Maurice Lambert
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.
"""
__license__ = license
__copyright__ = copyright

__all__ = ["RC4Encryption"]

from base64 import (
    b85encode,
    b64encode,
    b32encode,
    b16encode,
    b85decode,
    b64decode,
    b32decode,
    b16decode,
)
from argparse import Namespace, ArgumentParser, FileType
from binascii import a2b_hqx, b2a_hqx
from contextlib import suppress
from os import device_encoding
from hashlib import sha256
import argparse
import warnings
import locale
import sys


class RC4Encryption:

    """
    This class implements RC4 cipher.
    """

    def __init__(self, key: bytes):
        self.table = list(range(256))
        self.index1 = 0
        self.index2 = 0

        self.key = key
        self.cipher = []
        self.secret = None

        self.key_length = len(key)

    def reset(self, key: bytes) -> None:

        """
        This function reset key and other variables.
        """

        self.table = list(range(256))
        self.index1 = 0
        self.index2 = 0

        self.key = key
        self.cipher = []
        self.secret = None

        self.key_length = len(key)

    def make_key(self) -> None:

        """
        This function build the key.
        """

        for i in range(256):
            self.index1 = (
                self.index1 + self.table[i] + self.key[i % self.key_length]
            ) % 256
            self.table[i], self.table[self.index1] = (
                self.table[self.index1],
                self.table[i],
            )
        self.index1 = 0

    def crypt(self, secret: bytes) -> bytes:

        """
        This function crypt secret using RC4.
        """

        self.cipher = []
        self.secret = secret

        for car in self.secret:
            self.index1 = (self.index1 + 1) % 256
            self.index2 = (self.table[self.index1] + self.index2) % 256
            self.table[self.index1], self.table[self.index2] = (
                self.table[self.index2],
                self.table[self.index1],
            )
            self.cipher.append(
                car
                ^ self.table[(self.table[self.index1] + self.table[self.index2]) % 256]
            )
        self.cipher = bytes(self.cipher)

        return self.cipher


def parse_args() -> Namespace:

    """
    This function parse command line arguments.
    """

    parser = ArgumentParser(description="This file performs RC4 encryption.")

    input_ = parser.add_mutually_exclusive_group(required=True)
    input_.add_argument(
        "--input-file",
        "--i-file",
        "-i",
        type=FileType("rb"),
        default=sys.stdin,
        help="The file to be encrypted.",
        nargs="?",
    )
    input_.add_argument(
        "--input-string", "--string", "-s", help="The string to be encrypted."
    )

    parser.add_argument(
        "--output-file",
        "--o-file",
        "-o",
        type=FileType("w", encoding="latin-1"),
        default=sys.stdout,
        help="The output file.",
    )

    output_encoding = parser.add_mutually_exclusive_group()
    output_encoding.add_argument(
        "--base85",
        "--85",
        "-8",
        help="Base85 encoding as output format",
        action="store_true",
    )
    output_encoding.add_argument(
        "--base64",
        "--64",
        "-6",
        help="Base64 encoding as output format",
        action="store_true",
    )
    output_encoding.add_argument(
        "--base32",
        "--32",
        "-3",
        help="Base32 encoding as output format",
        action="store_true",
    )
    output_encoding.add_argument(
        "--base16",
        "--16",
        "-1",
        help="Base16 encoding as output format",
        action="store_true",
    )
    output_encoding.add_argument(
        "--uu", "-u", help="UU encoding as output format", action="store_true"
    )
    output_encoding.add_argument(
        "--output-encoding",
        "--o-encoding",
        "-e",
        help="Output encoding.",
        choices={"base85", "base64", "base32", "base16", "uu"},
    )

    parser.add_argument(
        "--input-encoding",
        "--i-encoding",
        "-n",
        help="Input encoding.",
        choices={"base85", "base64", "base32", "base16", "uu"},
    )

    parser.add_argument(
        "--sha256",
        help="Use the sha256 of the key as the key.",
        action=argparse.BooleanOptionalAction,
        default=True,
    )
    parser.add_argument("key", help="Encryption key.")

    arguments = parser.parse_args()

    if arguments.input_file is None:
        arguments.input_file = sys.stdin

    return arguments


def output_encoding(data: bytes, arguments: Namespace) -> bytes:

    """
    This function returns encoded data.
    """

    if arguments.base85 or arguments.output_encoding == "base85":
        encoding = b85encode
    elif arguments.base64 or arguments.output_encoding == "base64":
        encoding = b64encode
    elif arguments.base32 or arguments.output_encoding == "base32":
        encoding = b32encode
    elif arguments.base16 or arguments.output_encoding == "base16":
        encoding = b16encode
    elif arguments.uu or arguments.output_encoding == "uu":
        warnings.simplefilter("ignore")
        data = b2a_hqx(data)
        warnings.simplefilter("default")
        return data

    return encoding(data)


def input_encoding(data: bytes, encoding: str) -> bytes:

    """
    This function returns decoded data.
    """

    if encoding == "base85":
        decoding = b85decode
    elif encoding == "base64":
        decoding = b64decode
    elif encoding == "base32":
        decoding = b32decode
    elif encoding == "base16":
        decoding = b16decode
    elif encoding == "uu":
        warnings.simplefilter("ignore")
        data = a2b_hqx(data)
        warnings.simplefilter("default")
        return data

    return decoding(data)


def get_key(arguments: Namespace) -> bytes:

    """
    This function returns the key (256 bits).
    """

    if arguments.sha256:
        return sha256(arguments.key.encode()).digest()
    return arguments.key.encode()


def get_data(arguments: Namespace) -> bytes:

    """
    This function returns data to encrypt/decrypt.
    """

    if arguments.input_string and arguments.input_encoding:
        return input_encoding(arguments.input_string, arguments.input_encoding)
    elif arguments.input_string:
        return arguments.input_string
    elif arguments.input_encoding:
        return input_encoding(arguments.input_file.read(), arguments.input_encoding)
    else:
        return arguments.input_file.read()


def get_encodings():

    """
    This function returns the probable encodings.
    """

    encoding = locale.getpreferredencoding()
    if encoding is not None:
        yield encoding

    encoding = device_encoding(0)
    if encoding is not None:
        yield encoding

    yield "utf-8"  # Default for Linux
    yield "cp1252"  # Default for Windows
    yield "latin-1"  # Can read all files


def decode_output(data: bytes) -> str:

    """
    This function decode outputs (try somes encoding).
    """

    output = None
    for encoding in get_encodings():
        with suppress(UnicodeDecodeError):
            output = data.decode(encoding)
            return output


def main() -> None:

    """
    This function executes this file from the command line.
    """

    arguments = parse_args()

    if arguments.input_string:
        arguments.input_string = arguments.input_string.encode("utf-8")

    rc4 = RC4Encryption(get_key(arguments))
    rc4.make_key()

    format_output = any(
        [
            arguments.base85,
            arguments.base64,
            arguments.base32,
            arguments.base16,
            arguments.uu,
            arguments.output_encoding,
        ]
    )

    rc4.crypt(get_data(arguments))

    if format_output:
        arguments.output_file.write(
            decode_output(output_encoding(rc4.cipher, arguments))
        )
    else:
        arguments.output_file.write(decode_output(rc4.cipher))


if __name__ == "__main__":
    main()
    sys.exit(0)
