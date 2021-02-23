[![Build Status](https://travis-ci.com/bschoening/fpe.svg?branch=main)](https://travis-ci.com/bschoening/fpe)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

# ff3 - Format Preserving Encryption in Python

An implementation of the NIST approved Format Preserving Encryption (FPE) FF3 algorithm in Python.

* [NIST Recommendation SP 800-38G](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38G.pdf)

This package follows the FF3 algorithum for Format Preserving Encryption as described in the March 2016 NIST publication _Methods for Format-Preserving Encryption_, and revised on Feburary 28th, 2020 with a draft update for FF3-1.

Changes to minimum domain size and revised tweak length have been partially implemented in this package with updates to domain size. It is expected that the final standard will provide new test vectors necessary to change the tweak lengths to 56 bits.  Currently, tweaks remain set to 64 bits.

## Requires

This project was built and tested with Python 3.7 and later versions.  It requires the pycryptodome library:

`pip3 install pycryptodome`

## Installation

Install this project with pip:

`pip3 install ff3`

## Testing

There are official [test vectors](http://csrc.nist.gov/groups/ST/toolkit/examples.html) for FF3 provided by NIST, which are used for testing in this package.

To run unit tests on this implementation, including all test vectors from the NIST specification, run the command:

  1. `python3 ff3_test.py`

## Code Example

The example code below can help you get started.

```python3

from ff3 import FF3Cipher

key = "EF4359D8D580AA4F7F036D6F04FC6A94"
tweak = "D8E7920AFA330A73"
c = FF3Cipher(10, key, tweak)

plaintext = "4000001234567899"
ciphertext = c.encrypt(plaintext)
decrypted = c.decrypt(ciphertext)

print("Original: " + plaintext)
print("Ciphertext: " + ciphertext)
print("Decrypted: " + decrypted)

```

## Usage

FPE can be used for sensitive data tokenization, especially in regards to PCI and cryptographically reversible tokens. This implementation does not provide any guarantees regarding PCI DSS or other validation.

It's important to note that, as with any cryptographic package, managing and protecting the key appropriately to your situation is crucial. This package does not provide any guarantees regarding the key in memory.

## Implementation Notes

This implementation was originally based upon the [Capital One Go implemntation](https://github.com/capitalone/fpe).  It follows the algorithm as outlined in the NIST specification as closely as possible, including naming.

While all test vectors pass, this package has not otherwise been extensively tested.

As of Python 3.7, the standard library's [int](https://docs.python.org/3/library/functions.html#int) package supports radices/bases up to 36. Therefore, this release supports a max base of 36, which can contain numeric digits 0-9 and lowercase alphabetic characters a-z.

The django.utils.baseconv module supports base 62 and could be used to increase the radix range.

The cryptographic library used is [PyCryptodome](https://pypi.org/project/pycryptodome/) for AES encryption. FF3 uses a single-block with an IV of 0, which is effectively ECB mode. AES is also the only block cipher function which matches the requirement of the FF3 spec.

The domain size was revised in FF3-1 to radix<sup>minLen</sup> >= 1,000,000 and is represented by the constant `DOMAIN_MIN` in `ff3.py`. FF3-1 is in draft status and updated 56-bit test vectors are not yet available.

The tweak is required in the initial `FF3Cipher` constructor, but can optionally be overriden in each `encrypt` and `decrypt` call. This is similar to passing an IV or nonce when creating an encryptor object.

## Author

Brad Schoening

## License

This project is licensed under the terms of the [Apache 2.0 license](https://www.apache.org/licenses/LICENSE-2.0).
