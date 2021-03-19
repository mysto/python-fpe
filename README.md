[![Build Status](https://travis-ci.com/mysto/python-fpe.svg?branch=main)](https://travis-ci.com/mysto/python-fpe)
[![Coverage Status](https://coveralls.io/repos/github/mysto/python-fpe/badge.svg?branch=main)](https://coveralls.io/github/mysto/python-fpe?branch=main)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Downloads](https://pepy.tech/badge/ff3)](https://pepy.tech/project/ff3)

# ff3 - Format Preserving Encryption in Python

An implementation of the NIST approved Format Preserving Encryption (FPE) FF3 algorithm in Python.

* [NIST Recommendation SP 800-38G](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38G.pdf)

This package follows the FF3 algorithum for Format Preserving Encryption as described in the March 2016 NIST publication _Methods for Format-Preserving Encryption_, and revised on Feburary 28th, 2020 with a draft update for FF3-1.

Changes to minimum domain size and revised tweak length have been partially implemented in this package with updates to domain size. It is expected that the final standard will provide new test vectors necessary to change the tweak lengths to 56 bits.  Currently, tweaks remain set to 64 bits.

## Requires

This project was built and tested with Python 3.6 and later versions.  It requires the pycryptodome library:

`pip3 install pycryptodome`

## Installation

Install this project with pip:

`pip3 install ff3`

## Usage

FF3 is a Feistel ciphers, and Feistel ciphers are initialized with a radix representing an alphabet.  
Practial radix limits of 36 in python means the following radix values are typical:
* radix 10: digits 0..9
* radix 26: alphabetic a-z
* radix 36: alphanumeric 0..9, a-z

Special characters and international character sets, such as those found in UTF-8, would require a larger radix, and are not supported. 
Also, all elements in a plaintext string share the same radix. Thus, an identification number that consists of a letter followed 
by 6 digits (e.g. A123456) cannot be correctly encrypted by FPE while preserving this convention.

Input plaintext has maximum length restrictions based upon the chosen radix (2 * floor(96/log2(radix))):
* radix 10: 56 
* radix 26: 40
* radix 36: 36

To work around string length, its possible to encode longer text in chunks.

As with any cryptographic package, managing and protecting the key(s) is crucial. The tweak is generally not kept secret.
This package does not protect the key in memory.

## Code Example

The example code below can help you get started.

```python3

from ff3 import FF3Cipher

key = "EF4359D8D580AA4F7F036D6F04FC6A94"
tweak = "D8E7920AFA330A73"
c = FF3Cipher(key, tweak)

plaintext = "4000001234567899"
ciphertext = c.encrypt(plaintext)
decrypted = c.decrypt(ciphertext)

print("Original: " + plaintext)
print("Ciphertext: " + ciphertext)
print("Decrypted: " + decrypted)

```
## Testing

There are official [test vectors](https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/examples/ff3samples.pdf) for FF3 provided by NIST, which are used for testing in this package.

To run unit tests on this implementation, including all test vectors from the NIST specification, run the command:

  1. `python3 ff3_test.py`

## FF3 Algorithum

The FF3 algorithum is a tweakable block cipher based on an eight round Feistel cipher. A block cipher operates on fixed-length groups of bits, called blocks. A Feistel Cipher is not a specific cipher,
but a design model.  The encryption process consisting of eight rounds of 
processing of the plaintext, each round applies an internal round function followed by transformation steps.

The round function applies AES encryption in ECB mode, which is performed each iteration 
on alternating halves of the text being encrypted. The *key* value in FF3 is used only to initialize the AES cipher. Thereafter
the *tweak* is used together with the intermediate encrypted text as input to the round function.

In AES ECB mode, the total number of bits in the plaintext must be a multiple of the block size. 
## Implementation Notes

This implementation was originally based upon the [Capital One Go implemntation](https://github.com/capitalone/fpe).  It follows the algorithm as outlined in the NIST specification as closely as possible, including naming.

FPE can be used for sensitive data tokenization, especially with PCI and cryptographically reversible tokens. This implementation does not provide any guarantees regarding PCI DSS or other validation.

While all test vectors pass, this package has not otherwise been extensively tested.

As of Python 3.7, the standard library's [int](https://docs.python.org/3/library/functions.html#int) package supports radices/bases up to 36. Therefore, this release supports a max base of 36, which can contain numeric digits 0-9 and lowercase alphabetic characters a-z.

The django.utils.baseconv module supports base 62 and could be used to increase the radix range.

The cryptographic library used is [PyCryptodome](https://pypi.org/project/pycryptodome/) for AES encryption. FF3 uses a single-block with an IV of 0, which is effectively ECB mode. AES ECB is the only block cipher function which matches the requirement of the FF3 spec.

The domain size was revised in FF3-1 to radix<sup>minLen</sup> >= 1,000,000 and is represented by the constant `DOMAIN_MIN` in `ff3.py`. FF3-1 is in draft status and updated 56-bit test vectors are not yet available.

The tweak is required in the initial `FF3Cipher` constructor, but can optionally be overriden in each `encrypt` and `decrypt` call. This is similar to passing an IV or nonce when creating an encryptor object.

## Author

Brad Schoening

## License

This project is licensed under the terms of the [Apache 2.0 license](https://www.apache.org/licenses/LICENSE-2.0).
