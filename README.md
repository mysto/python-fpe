[![Build Status](https://app.travis-ci.com/PuspenduBanerjee/python-fpe.svg?branch=main)](https://travis-ci.com/PuspenduBanerjee/python-fpe)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![PyPI version](https://badge.fury.io/py/pyFPE.svg)](https://badge.fury.io/py/pyFPE)

# ff3 - Format Preserving Encryption in Python

An implementation of the NIST approved Format Preserving Encryption (FPE) FF3 algorithm in Python.

* [NIST Recommendation SP 800-38G](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38G.pdf)
* [NIST FF3-1](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38Gr1-draft.pdf)

This package follows the FF3 algorithum for Format Preserving Encryption as described in the March 2016 NIST publication _Methods for Format-Preserving Encryption_, and revised on Feburary 28th, 2020 with a draft update for FF3-1.

Changes to minimum domain size and revised tweak length have been implemented in this package.
Tweaks can be 56 or 64 bits, but NIST has only published test vectors for 64-bit tweaks.  It is expected the final
standard will provide updated test vectors necessary to change the 
tweak lengths to 56 bits.  

## Requires

This project was built and tested with Python 3.6 and later versions.  It requires the pycryptodome library:

`pip3 install pycryptodome`

## Installation

Install this project with pip:

`pip3 install pyFPE`

## Usage

FF3 is a Feistel cipher, and Feistel ciphers are initialized with a radix representing an alphabet.  
Practial radix limits of 36 in python means the following radix values are typical:
* radix 10: digits 0..9
* radix 36: alphanumeric 0..9, a-z
* radix 64: alphanumeric 0..9, a-z, A-Z, '-

Special characters and international character sets, such as those found in UTF-8, would require a larger radix, and are not supported. 
Also, all elements in a plaintext string share the same radix. Thus, an identification number that consists of a letter followed 
by 6 digits (e.g. A123456) cannot be correctly encrypted by FPE while preserving this convention.

Input plaintext has maximum length restrictions based upon the chosen radix (2 * floor(96/log2(radix))):
* radix 10: 56
* radix 36: 36
* radix 64: 32

To work around string length, its possible to encode longer text in chunks before and after encryption.
As transparent chunking feature has been added, such pre-processing for chunking is not required, but a developer can achieve greater control on chunk-size.

As with any cryptographic package, managing and protecting the key(s) is crucial. The tweak is generally not kept secret.
This package does not protect the key in memory.

## Code Example

The example code below uses the default domain [0-9] and can help you get started.

```python3

from pyfpe_ff3 import FF3Cipher

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

The example code below uses the default domain [0-9] to anonymize US SSN by scrubbing non-digit characters and reformat the final result. 
It can be applied for Phone Numbers as well.
```python3
from pyfpe_ff3 import FF3Cipher, format_align_digits
key = "EF4359D8D580AA4F7F036D6F04FC6A94"
tweak = "D8E7920AFA330A73"
c = FF3Cipher(key, tweak)
actual_ssn = "845-06-9423"
anonymized_ssn = format_align_digits(c.encrypt(actual_ssn),actual_ssn)
print(f"{actual_ssn} -> {anonymized_ssn}")
```

Following example shows transparent chunking for length limit ( say 32 chaacters for radix 64). 
This way we can handle larger plaintext to cipher and decipher. 
```python3


from pyfpe_ff3 import FF3Cipher

key = "EF4359D8D580AA4F7F036D6F04FC6A94"
tweak = "A8E7920AFA330A73"
c = FF3Cipher(key, tweak, radix=64, allow_small_domain= True)
plaintext = "Donaudampfschifffahrtsgesellschaftskapitaenswitwe"*2  # 49x2 =98 characters
ciphertext = c.encrypt(plaintext)
decrypted = c.decrypt(ciphertext)
print(f"{plaintext} -> \n{ciphertext} -> \n{decrypted}")

```

## Testing

There are official [test vectors](https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/examples/ff3samples.pdf) for FF3 provided by NIST, which are used for testing in this package.

To run unit tests on this implementation, including all test vectors from the NIST specification, run the command:

  1. `python tests/pyfpe_ff3_test.py`
  2. or `python setup.py test`

## FF3 Algorithum

The FF3 algorithum is a tweakable block cipher based on an eight round Feistel cipher. A block cipher operates on fixed-length groups of bits, called blocks. A Feistel Cipher is not a specific cipher,
but a design model.  This FF3 Feistel encryption consisting of eight rounds of processing
the plaintext. Each round applies an internal function or _round function_, followed by transformation steps.

The FF3 round function uses AES encryption in ECB mode, which is performed each iteration 
on alternating halves of the text being encrypted. The *key* value is used only to initialize the AES cipher. Thereafter
the *tweak* is used together with the intermediate encrypted text as input to the round function.

## Implementation Notes

This implementation was originally based upon the [Capital One Go implemntation](https://github.com/capitalone/fpe).  It follows the algorithm as outlined in the NIST specification as closely as possible, including naming.

FPE can be used for data tokenization of sensitive data which is cryptographically reversible. This implementation does not provide any guarantees regarding PCI DSS or other validation.

While all NIST standard test vectors pass, this package has not otherwise been extensively tested.

As of Python 3.7, the standard library's [int](https://docs.python.org/3/library/functions.html#int) package supports radices/bases up to 36. Therefore, this release supports a max base of 36, which can contain numeric digits 0-9 and lowercase alphabetic characters a-z.

As an enhancement to increase the radix range, the standard libary _base64_ package supports base 64 for string conversion. The Fiestel algorithum requires Integer conversion is well and the result would need to as performant as existing BigInt.
Added int2 function to convert to support radix 64 [0..9, a-z, A-Z, '-].

The cryptographic library used is [PyCryptodome](https://pypi.org/project/pycryptodome/) for AES encryption. FF3 uses a single-block with an IV of 0, which is effectively ECB mode. AES ECB is the only block cipher function which matches the requirement of the FF3 spec.

The domain size was revised in FF3-1 to radix<sup>minLen</sup> >= 1,000,000 and is represented by the constant `DOMAIN_MIN` in `ff3.py`. FF3-1 is in draft status and updated 56-bit test vectors are not yet available. Small domains can still be allowed using `allow_small_domain` boolean value in constructor.

The tweak is required in the initial `FF3Cipher` constructor, but can optionally be overriden in each `encrypt` and `decrypt` call. This is similar to passing an IV or nonce when creating an encryptor object.

## Authors

Brad Schoening & Puspendu Banerjee <puspendu.banerjee@gmail.com>

## License

This project is licensed under the terms of the [Apache 2.0 license](https://www.apache.org/licenses/LICENSE-2.0).
