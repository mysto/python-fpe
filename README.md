[![Build Status](https://travis-ci.com/mysto/python-fpe.svg?branch=main)](https://travis-ci.com/mysto/python-fpe)
[![Coverage Status](https://coveralls.io/repos/github/mysto/python-fpe/badge.svg?branch=main)](https://coveralls.io/github/mysto/python-fpe?branch=main)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Downloads](https://pepy.tech/badge/ff3)](https://pepy.tech/project/ff3)

# ff3 - Format Preserving Encryption in Python

An implementation of the NIST approved Format Preserving Encryption (FPE) FF3 algorithm in Python.

This package follows the FF3 algorithm for Format Preserving Encryption as described in the March 2016 NIST publication 800-38G _Methods for Format-Preserving Encryption_, 
and revised on February 28th, 2019 with a draft update for FF3-1.

* [NIST Recommendation SP 800-38G (FF3)](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38G.pdf)
* [NIST Recommendation SP 800-38G Revision 1 (FF3-1)](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38Gr1-draft.pdf)

Changes to minimum domain size and revised tweak length have been implemented in this package.
Tweaks can be 56 or 64 bits, but NIST has only published test vectors for 64-bit tweaks.  It is expected the final
standard will provide updated test vectors necessary to change the tweak lengths to 56 bits.

## Requires

This project was built and tested with Python 3.6 and later versions.  The only dependency is [PyCryptodome](https://pycryptodome.readthedocs.io).

## Installation

For a normal install of the latest PyPI release with pip:

`pip3 install ff3`

To instead install the development version:

```bash
git clone https://github.com/mysto/python-fpe.git
cd python-fpe
pip3 install --editable .
```

Before contributing any pull requests, you will need to first fork this repository and change the remote origin to reflect your fork:

```bash
git remote set-url origin git@github.com:YOUR-GITHUB-USERNAME/python-fpe.git
```

To uninstall:

```bash
pip3 uninstall ff3
```

## Usage

FF3 is a Feistel cipher, and Feistel ciphers are initialized with a radix representing an alphabet. The number of 
characters in an alphabet is called the _radix_.
The following radix values are typical:

* radix 10: digits 0..9
* radix 36: alphanumeric 0..9, a-z
* radix 62: alphanumeric 0..9, a-z, A-Z

Special characters and international character sets, such as those found in UTF-8, are supported by specifying a custom alphabet.
Also, all elements in a plaintext string share the same radix. Thus, an identification number that consists of a letter followed 
by 6 digits (e.g. A123456) cannot be correctly encrypted by FPE while preserving this convention.

Input plaintext has maximum length restrictions based upon the chosen radix (2 * floor(96/log2(radix))):

* radix 10: 56
* radix 36: 36
* radix 62: 32

To work around string length, its possible to encode longer text in chunks.

As with any cryptographic package, managing and protecting the key(s) is crucial. The tweak is generally not kept secret.
This package does not protect the key in memory.

## Code Example

The example code below uses the default domain [0-9] and can help you get started.

```python3

from ff3 import FF3Cipher

key = "EF4359D8D580AA4F7F036D6F04FC6A94"
tweak = "D8E7920AFA330A73"
c = FF3Cipher(key, tweak)

plaintext = "4000001234567899"
ciphertext = c.encrypt(plaintext)
decrypted = c.decrypt(ciphertext)

print(f"{plaintext} -> {ciphertext} -> {decrypted}")

# format encrypted value
ccn = f"{ciphertext[:4]} {ciphertext[4:8]} {ciphertext[8:12]} {ciphertext[12:]}"
print(f"Encrypted CCN value with formatting: {ccn}")
```
## Custom alphabets

To use an alphabet consisting of the uppercase letters A-F (radix=6), we can continue
from the above code example with:

```python3
c6 = FF3Cipher.withCustomAlphabet(key, tweak, "ABCDEF")
plaintext = "DEADBEEF"
ciphertext = c6.encrypt(plaintext)
decrypted = c6.decrypt(ciphertext)
print(f"{plaintext} -> {ciphertext} -> {decrypted}")
```

## Testing

There are official [test vectors](https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/examples/ff3samples.pdf) for FF3 provided by NIST, which are used for testing in this package.

To run unit tests on this implementation, including all test vectors from the NIST specification, run the command:

```bash
python3 -m ff3.ff3_test
```

## Performance Benchmarks

The Mysto FF3 was benchmarked on a MacBook Air (1.1 GHz Quad-Core Intel Core i5) 
performing 70,000 tokenization per second with random 8 character data input.

To run the performance tests:
```bash
python3 ff3_perf.py
```

## The FF3 Algorithm

The FF3 algorithm is a tweakable block cipher based on an eight round Feistel cipher. A block cipher operates on fixed-length groups of bits, called blocks. A Feistel Cipher is not a specific cipher,
but a design model.  This FF3 Feistel encryption consisting of eight rounds of processing
the plaintext. Each round applies an internal function or _round function_, followed by transformation steps.

The FF3 round function uses AES encryption in ECB mode, which is performed each iteration 
on alternating halves of the text being encrypted. The *key* value is used only to initialize the AES cipher. Thereafter
the *tweak* is used together with the intermediate encrypted text as input to the round function.

## Other FPE Algorithms

Only FF1 and FF3 have been approved by NIST for format preserving encryption. There are patent claims on FF1 which allegedly include open source implementations. Given the issues raised in ["The Curse of Small Domains: New Attacks on Format-Preserving Encryption"](https://eprint.iacr.org/2018/556.pdf) by Hoang, Tessaro and Trieu in 2018, it is prudent to be very cautious about using any FPE that isn't a standard and hasn't stood up to public scrutiny.

## Implementation Notes

This implementation was originally based upon the [Capital One Go implementation](https://github.com/capitalone/fpe).  It follows the algorithm as outlined in the NIST specification as closely as possible, including naming.

FPE can be used for data tokenization of sensitive data which is cryptographically reversible. This implementation does not provide any guarantees regarding PCI DSS or other validation.

While all NIST standard test vectors pass, this package has not otherwise been extensively tested.

The cryptographic library used is [PyCryptodome](https://pypi.org/project/pycryptodome/) for AES encryption. FF3 uses a single-block with an IV of 0, which is effectively ECB mode. AES ECB is the only block cipher function which matches the requirement of the FF3 spec.

The domain size was revised in FF3-1 to radix<sup>minLen</sup> >= 1,000,000 and is represented by the constant `DOMAIN_MIN` in `ff3.py`. FF3-1 is in draft status and updated 56-bit test vectors are not yet available.

The tweak is required in the initial `FF3Cipher` constructor, but can optionally be overridden in each `encrypt` and `decrypt` call. This is similar to passing an IV or nonce when creating an encrypter object.

## Author

Brad Schoening

## License

This project is licensed under the terms of the [Apache 2.0 license](https://www.apache.org/licenses/LICENSE-2.0).
