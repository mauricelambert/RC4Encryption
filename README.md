![RC4Encryption logo](https://mauricelambert.github.io/info/python/security/RC4Encryption_small.png "RC4Encryption logo")

# RC4Encryption

## Description

This package implement the RC4 encryption.

## Requirements

This package require :
 - python3
 - python3 Standard Library

## Installation
```bash
pip install RC4Encryption
```

## Usages

### Recommended options

Some encoding errors are possible using the command line, I recommend using base64.

```bash
rc4 [key] -6 -o [secrets.cipher] -i [secrets.file]            # encryption
rc4 [key] -n base64 -i [secrets.cipher] -o [decipher.file] -d # decryption
```

### Command line

#### Module

```bash
python3 -m RC4Encryption rc4key -s secrets
```

#### Python executable

```bash
python3 RC4Encryption.pyz rc4key -s secrets
```

#### Command

##### Basic

```bash
rc4 rc4key -s secrets                               # encrypt "secrets" with rc4key sha256 as key
```

##### Advanced

```bash
rc4 rc4key -s secrets              # encrypt "secrets" with rc4key sha256 as key
echo secrets| rc4 rc4key --no-sha256 -i             # encrypt "secrets\n" with b'rc4key' as key
rc4 rc4key -i secrets.txt                           # encrypt secrets.txt file with rc4key sha256 as key
rc4 rc4key -o encrypt.rc4 -s secrets                # encrypt "secrets" with rc4key sha256 as key and redirect the output to the encrypt.rc4 file
rc4 rc4key -i encrypt.rc4 -d                        # decrypt encrypt.rc4 with rc4key sha256 as key

# I do not recommend using encoding (input or output) with a large file size

## INPUT  ENCODING

rc4 rc4key -n base64 -s c2VjcmV0cw==                # encrypt "secrets" with rc4key sha256 as key ("c2VjcmV0cw==" = base64("secrets"))

## OUTPUT ENCODING

rc4 rc4key -s secrets -8                            # encrypt "secrets" with rc4key sha256 as key, base85-encoded output
rc4 rc4key -s secrets -6                            # encrypt "secrets" with rc4key sha256 as key, base64-encoded output
rc4 rc4key -s secrets -3                            # encrypt "secrets" with rc4key sha256 as key, base30-encoded output
rc4 rc4key -s secrets -1                            # encrypt "secrets" with rc4key sha256 as key, base16-encoded output
rc4 rc4key -s secrets -u                            # encrypt "secrets" with rc4key sha256 as key, uu-encoded output
```

### Python script

```python
from RC4Encryption import RC4Encryption

rc4 = RC4Encryption(b'key')
rc4.make_key()
cipher = rc4.crypt(b'secrets')
cipher_continuation = rc4.crypt(b'secrets')


rc4.reset(b'key')
rc4.make_key()
decipher = rc4.crypt(cipher)
decipher_continuation = rc4.crypt(cipher_continuation)
```

## Links

 - [Github Page](https://github.com/mauricelambert/RC4Encryption/)
 - [Documentation](https://mauricelambert.github.io/info/python/security/RC4Encryption.html)
 - [Pypi package](https://pypi.org/project/RC4Encryption/)
 - [Executable](https://mauricelambert.github.io/info/python/security/RC4Encryption.pyz)

## Help

```text
usage: RC4Encryption.py [-h] (--input-file [INPUT_FILE] | --input-string INPUT_STRING) [--output-file OUTPUT_FILE]
                        [--base85 | --base64 | --base32 | --base16 | --uu | --output-encoding {uu,base16,base64,base32,base85}] [--input-encoding {uu,base16,base64,base32,base85}] [--sha256 | --no-sha256]
                        key

This file performs RC4 encryption.

positional arguments:
  key                   Encryption key.

optional arguments:
  -h, --help            show this help message and exit
  --input-file [INPUT_FILE], --i-file [INPUT_FILE], -i [INPUT_FILE]
                        The file to be encrypted.
  --input-string INPUT_STRING, --string INPUT_STRING, -s INPUT_STRING
                        The string to be encrypted.
  --output-file OUTPUT_FILE, --o-file OUTPUT_FILE, -o OUTPUT_FILE
                        The output file.
  --base85, --85, -8    Base85 encoding as output format
  --base64, --64, -6    Base64 encoding as output format
  --base32, --32, -3    Base32 encoding as output format
  --base16, --16, -1    Base16 encoding as output format
  --uu, -u              UU encoding as output format
  --output-encoding {uu,base16,base64,base32,base85}, --o-encoding {uu,base16,base64,base32,base85}, -e {uu,base16,base64,base32,base85}
                        Output encoding.
  --input-encoding {uu,base16,base64,base32,base85}, --i-encoding {uu,base16,base64,base32,base85}, -n {uu,base16,base64,base32,base85}
                        Input encoding.
  --sha256, --no-sha256
                        Use the sha256 of the key as the key. (default: True)
```

## Licence

Licensed under the [GPL, version 3](https://www.gnu.org/licenses/).
