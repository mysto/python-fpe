# ff3 - Format Preserving Encryption in Python

An implementation of the NIST approved Format Preserving Encryption (FPE) FF3 algorithm in Python.

* [NIST Recommendation SP 800-38G](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38G.pdf)

This follows the FF3 schemes for Format Preserving Encryption outlined in the NIST Recommendation, released in March 2016. 

NIST published on Feburary 28th, 2020 an update to the standard, FF3-1.  These changes to minimum domain size and revised tweak length have not
yet been updated here to FF3-1.

## Requires

This project was built and tested with Python 3.7.  It requires the pycryptodome library:

`pip install pycryptodome`

## Installation

Install this project with pip:

`pip install ff3`

## Testing

There are official [test vectors](http://csrc.nist.gov/groups/ST/toolkit/examples.html) for FF3 provided by NIST, which are used for testing in this package.

To run unit tests on this implementation with all test vectors from the NIST link above, run the unit tests:

  1. `python ff3_test.py`

## Code Example

The example code below can help you get started.

```python

from ff3 import FF3Cipher

key = "EF4359D8D580AA4F7F036D6F04FC6A94"
tweak = "D8E7920AFA330A73"
plaintext = "890121234567890000"

c = FF3Cipher(10, key, tweak)
ciphertext = c.encrypt(plaintext)
decrypted = c.decrypt(ciphertext)

print("Original: " + plaintext)
print("Ciphertext: " + ciphertext)
print("Decrypted: " + decrypted)

```

## Usage notes

FPE can be used for sensitive data tokenization, especially in regards to PCI and cryptographically reversible tokens. This implementation does not provide any guarantees regarding PCI DSS or other validation.

It's important to note that, as with any cryptographic package, managing and protecting the key appropriately to your situation is crucial. This package does not provide any guarantees regarding the key in memory.

## Implementation Notes

This implementation was based upon the [Capital One Go implemntation](https://github.com/capitalone/fpe).  It follows the algorithm as outlined in the NIST specification as closely as possible, including naming.  

While the test vectors all pass, this package has not otherwise been extensively tested. 

As of Python 3.7, the standard library's [int](https://docs.python.org/3/library/functions.html#int) package supports radices/bases up to 36. Therefore, this release supports a max base of 36, which can contain numeric digits 0-9 and lowercase alphabetic characters a-z.

The django.utils.baseconv module supports base 62 and could be used to increase the radix range.

The cryptographic primitive used is the [Python Cryptography Toolkit (pycrypto)](https://pypi.org/project/pycrypto) for AES encryption. It uses a single-block with an IV of 0, which is effectively ECB mode. AES is also the only block cipher function matching the requirement of the FF3 spec.

The domain size was revised in FF3-1 to radix^minLen >= 1,000,000 which is represented by the constant `FEISTEL_MIN` in `ff3.py`. FF3-1 remains a draft and new 56-bit test vectors are not yet available.  This implementation follows the draft FF3-1 specification published on Feburary 2019.

Regarding how the "tweak" is used as input: the tweak is required in the initial `FF3Cipher` constructor, but can optionally be overriden of in each `Encrypt` and `Decrypt` call. This usage makes it similar to passing an IV or nonce when creating an encryptor object.

## Author

Brad Schoening

## License

This project is licensed under the terms of the [Apache 2.0 license](https://www.apache.org/licenses/LICENSE-2.0).
