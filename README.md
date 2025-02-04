[![Build Status](https://github.com/mysto/python-fpe/actions/workflows/build-py.yml/badge.svg)](https://github.com/mysto/python-fpe/actions)
[![Coverage Status](https://coveralls.io/repos/github/mysto/python-fpe/badge.svg?branch=main)](https://coveralls.io/github/mysto/python-fpe?branch=main)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/ff3)
[![Downloads](https://pepy.tech/badge/ff3)](https://pepy.tech/project/ff3)
[![PyPI version](https://badge.fury.io/py/ff3.svg)](https://badge.fury.io/py/ff3)

<p align="center">
  <a href="https://privacylogistics.com/">
    <img
      alt="Mysto"
      src="https://privacylogistics.com/Mysto-logo.jpg"
    />
  </a>
</p>

# FF3 - Format Preserving Encryption in Python

An implementation of the NIST approved FF3 and FF3-1 Format Preserving Encryption (FPE) algorithms in Python.

This package implements the FF3 algorithm for Format Preserving Encryption as described in the March 2016 NIST publication 800-38G _Methods for Format-Preserving Encryption_,
and revised on February 28th, 2019 with a draft update for FF3-1.

* [NIST Recommendation SP 800-38G (FF3)](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38G.pdf)
* [NIST Recommendation SP 800-38G Revision 1 (FF3-1)](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38Gr1-draft.pdf)

Changes to minimum domain size and revised tweak length have been implemented in this package with
support for both 64-bit and 56-bit tweaks. NIST has only published official test vectors for 64-bit tweaks, 
but draft ACVP test vectors have been used for testing FF3-1. It is expected the final
NIST standard will provide updated test vectors with 56-bit tweak lengths.

## Installation

`pip3 install ff3`

## Usage

FF3 is a Feistel cipher, and Feistel ciphers are initialized with a radix representing an alphabet. The number of
characters in an alphabet is called the _radix_.
The following radix values are typical:

* radix 10: digits 0..9
* radix 36: alphanumeric 0..9, a-z
* radix 62: alphanumeric 0..9, a-z, A-Z

Special characters and international character sets, such as those found in UTF-8, are supported by specifying a custom alphabet.
Also, all elements in a plaintext string share the same radix. Thus, an identification number that consists of an initial letter followed
by 6 digits (e.g. A123456) cannot be correctly encrypted by FPE while preserving this convention.

Input plaintext has maximum length restrictions based upon the chosen radix (2 * floor(96/log2(radix))):

* radix 10: 56
* radix 36: 36
* radix 62: 32

To work around string length, its possible to encode longer text in chunks.

The key length must be 128, 192, or 256 bits in length. The tweak is 7 bytes (FF3-1) or 8 bytes for the origingal FF3.

As with any cryptographic package, managing and protecting the key(s) is crucial. The tweak is generally not kept secret.
This package does not store the key in memory after initializing the cipher.

## Code Example

The example code below uses the default domain [0-9] and can help you get started.

```python3

from ff3 import FF3Cipher

key = "2DE79D232DF5585D68CE47882AE256D6"
tweak = "CBD09280979564"
c = FF3Cipher(key, tweak)

plaintext = "3992520240"
ciphertext = c.encrypt(plaintext)
decrypted = c.decrypt(ciphertext)

print(f"{plaintext} -> {ciphertext} -> {decrypted}")

# format encrypted value
ccn = f"{ciphertext[:4]} {ciphertext[4:8]} {ciphertext[8:12]} {ciphertext[12:]}"
print(f"Encrypted CCN value with formatting: {ccn}")
```
## CLI Example

This package installs the command line scripts ff3_encrypt and ff3_decrypt which can be run
from the Linux or Windows command line.

```bash
% ff3_encrypt 2DE79D232DF5585D68CE47882AE256D6 CBD09280979564 3992520240
8901801106
% ff3_decrypt 2DE79D232DF5585D68CE47882AE256D6 CBD09280979564 8901801106
3992520240

```


## Custom alphabets

Custom alphabets up to 256 characters are supported. To use an alphabet consisting of the uppercase letters A-F (radix=6), we can continue
from the above code example with:

```python3
c6 = FF3Cipher.withCustomAlphabet(key, tweak, "ABCDEF")
plaintext = "BADDCAFE"
ciphertext = c6.encrypt(plaintext)
decrypted = c6.decrypt(ciphertext)

print(f"{plaintext} -> {ciphertext} -> {decrypted}")
```
## Requires

This project was built and tested with Python 3.9 and later versions.  The only dependency is [PyCryptodome](https://pycryptodome.readthedocs.io).

## Testing

Official [test vectors](https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/examples/ff3samples.pdf) for FF3 provided by NIST,
are used for testing in this package. Also included are draft ACVP test vectors with 56-bit tweaks.

To run unit tests on this implementation, including all test vectors from the NIST specification, run the command:

```bash
python3 -m ff3.ff3_test
```

## Performance Benchmarks

The Mysto FF3 was benchmarked on a MacBook Air (1.1 GHz Quad-Core Intel Core i5)
performing 70,000 tokenization per second with random 8 character data input.

To run the performance tests:

```bash
python3 -m ff3.ff3_perf
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

While all NIST and ACVP test vectors pass, this package has not otherwise been extensively tested.

The cryptographic library used is [PyCryptodome](https://pypi.org/project/pycryptodome/) for AES encryption. FF3 uses a single-block with an IV of 0, which is effectively ECB mode. AES ECB is the only block cipher function which matches the requirement of the FF3 spec.

The domain size was revised in FF3-1 to radix<sup>minLen</sup> >= 1,000,000 and is represented by the constant `DOMAIN_MIN` in `ff3.py`. FF3-1 is in draft status.

The tweak is required in the initial `FF3Cipher` constructor, but can optionally be overridden in each `encrypt` and `decrypt` call. This is similar to passing an IV or nonce when creating an encrypter object.

## Developer Installation

To install the development version:

```bash
git clone https://github.com/mysto/python-fpe.git
cd python-fpe
pip3 install --editable .
```

Before contributing any pull requests, you will need to first fork this repository and change the remote origin to reflect your fork:

```bash
git remote set-url origin git@github.com:YOUR-GITHUB-USERNAME/python-fpe.git
```

## Author

Brad Schoening

## License

This project is licensed under the terms of the [Apache 2.0 license](https://www.apache.org/licenses/LICENSE-2.0).
