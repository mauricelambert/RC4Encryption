#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This package implements RC4 encryption.
#    Copyright (C) 2021, 2024  Maurice Lambert

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

>>> from urllib.request import urlopen, Request
>>> from json import dumps, load
>>> rc4 = RC4Encryption(b'key')
>>> rc4.make_key()
>>> cipher = rc4.encrypt(b'secrets')
>>> cipher.hex() == load(urlopen(Request("https://www.lddgo.net/api/RC4?lang=en", headers={"Content-Type": "application/json;charset=UTF-8"}, data=dumps({"inputContent":"secrets","inputPassword":"key","charset":"UTF-8","inputFormat":"string","outputFormat":"hex","encrypt":True}).encode())))["data"]
True
>>> cipher_continuation = rc4.encrypt(b'secrets')
>>> assert cipher_continuation != cipher
>>> rc4.reset(b'key')
>>> rc4.make_key()
>>> rc4.encrypt(cipher)
b'secrets'
>>> rc4.encrypt(cipher_continuation)
b'secrets'
>>> 

~# python3 RC4Encryption.py -s mydata mykey -1
3B1FE10F0025
~# python3 RC4Encryption.py -s 3B1FE10F0025 -n base16 mykey
mydata
~# python3 RC4Encryption.py -i secrets.file -6 -o cipher.b64 key
~# python3 RC4Encryption.py -o decipher.file -n base64 -i cipher.b64 key

1 items passed all tests:
  12 tests in RC4
12 tests in 14 items.
12 passed and 0 failed.
Test passed.
"""

__version__ = "0.0.2"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = "This package implements RC4 encryption."
license = "GPL-3.0 License"
__url__ = "https://github.com/mauricelambert/RC4Encryption"

copyright = """
RC4Encryption  Copyright (C) 2021, 2024  Maurice Lambert
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.
"""
__license__ = license
__copyright__ = copyright

print(copyright)

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
from locale import getpreferredencoding
from sys import exit, stdin, stdout
from warnings import simplefilter
from contextlib import suppress
from os import device_encoding
from typing import Iterable
from hashlib import sha256

try:
    from binascii import a2b_hqx, b2a_hqx
except ImportError:
    uu_encoding = False
else:
    uu_encoding = True


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
        This function resets key and other variables.
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
        This function builds the key.
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

    def encrypt(self, secret: bytes) -> bytes:
        """
        This function encrypts secret using RC4.
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
                ^ self.table[
                    (self.table[self.index1] + self.table[self.index2]) % 256
                ]
            )
        self.cipher = bytes(self.cipher)

        return self.cipher


def parse_args() -> Namespace:
    """
    This function parses command line arguments.
    """

    parser = ArgumentParser(description="This file performs RC4 encryption.")

    input_ = parser.add_mutually_exclusive_group(required=True)
    input_.add_argument(
        "--input-file",
        "--i-file",
        "-i",
        type=FileType("rb"),
        default=stdin.buffer,
        help="The secrets file to be encrypted.",
        nargs="?",
    )
    input_.add_argument(
        "--input-string", "--string", "-s", help="The string to be encrypted."
    )

    parser.add_argument(
        "--output-file",
        "--o-file",
        "-o",
        type=FileType("wb"),
        default=stdout.buffer,
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
    if uu_encoding:
        output_encoding.add_argument(
            "--uu",
            "-u",
            help="UU encoding as output format",
            action="store_true",
        )
    output_encoding.add_argument(
        "--output-encoding",
        "--o-encoding",
        "-e",
        help="Output encoding.",
        choices={"base85", "base64", "base32", "base16", "uu"}
        if uu_encoding
        else {"base85", "base64", "base32", "base16"},
    )

    parser.add_argument(
        "--input-encoding",
        "--i-encoding",
        "-n",
        help="Input encoding.",
        choices={"base85", "base64", "base32", "base16", "uu"}
        if uu_encoding
        else {"base85", "base64", "base32", "base16"},
    )

    parser.add_argument(
        "--sha256",
        help="Use the sha256 of the key as the key.",
        action="store_true",
        default=False,
    )
    parser.add_argument("key", help="Encryption key.")

    arguments = parser.parse_args()

    if arguments.input_file is None:
        arguments.input_file = stdin.buffer

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
    elif uu_encoding and (arguments.uu or arguments.output_encoding == "uu"):
        simplefilter("ignore")
        data = b2a_hqx(data)
        simplefilter("default")
        return data
    else:
        raise ValueError("Invalid encoding algorithm value")

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
    elif uu_encoding and encoding == "uu":
        simplefilter("ignore")
        data = a2b_hqx(data)
        simplefilter("default")
        return data
    else:
        raise ValueError("Invalid encoding algorithm value")

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

    if arguments.input_string:
        data = arguments.input_string
    else:
        data = arguments.input_file.read()

    if arguments.input_encoding:
        return input_encoding(data, arguments.input_encoding)

    return data


def get_encodings() -> Iterable[str]:
    """
    This function returns the probable encodings.
    """

    encoding = getpreferredencoding()
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
    This function decodes data (try probable encodings).
    """

    output = None
    for encoding in get_encodings():
        with suppress(UnicodeDecodeError):
            output = data.decode(encoding)
            return output


def main() -> int:
    """
    This function executes this file from the command line.
    """

    arguments = parse_args()

    if arguments.input_string:
        arguments.input_string = arguments.input_string.encode()

    rc4 = RC4Encryption(get_key(arguments))
    rc4.make_key()

    format_output = any(
        [
            arguments.base85,
            arguments.base64,
            arguments.base32,
            arguments.base16,
            arguments.uu if uu_encoding else None,
            arguments.output_encoding,
        ]
    )

    rc4.encrypt(get_data(arguments))

    if format_output:
        data = output_encoding(rc4.cipher, arguments)
    else:
        data = rc4.cipher

    arguments.output_file.write(data)


if __name__ == "__main__":
    exit(main())
