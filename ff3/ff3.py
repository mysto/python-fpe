"""

SPDX-Copyright: Copyright (c) Schoening Consulting, LLC
SPDX-License-Identifier: Apache-2.0
Copyright 2020 Schoening Consulting, LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.

"""

# Package ff3 implements the FF3 format-preserving encryption algorithm/scheme

import logging
import math
from Crypto.Cipher import AES
# from hexdump import hexdump

FEISTEL_MIN =  100  # 1M is currently recommended
NUM_ROUNDS =   8
BLOCK_SIZE =   16  # aes.BlockSize
TWEAK_LEN =    8
HALF_TWEAK_LEN = TWEAK_LEN // 2
MAX_RADIX =    36  # python int supports radix 2..36


def reverseString(aString):
    return aString[::-1]


"""
FF3 can encode an arbritary length string. This implementation uses an alternating Feistel with the
following parameters:
    128 bit key length
    Cipher Block Chain (CBC-MAC) round function
    64-bit tweak
    eight (8) rounds
    Modulo addition

An encoded string representation of x in the given base. Base must be between 2 and 36, inclusive. The result
uses the uses the lower-case letters 'a' to 'z' for digit values 10 to 3.  Currently unimplemented, the
upper-case letters 'A' to 'Z' would represent digit values 36 to 61.

FF3Cipher initializes a new FF3 Cipher for encryption or decryption with radix, key and tweak parameters.
"""


class FF3Cipher:
    def __init__(self, radix, key, tweak):

        self.radix = radix
        self.key = bytes.fromhex(key)
        self.tweak = tweak

        # Calculate min domain, minLength, per spec, radix^minLength >= 100.
        self.minLen = (math.ceil(math.log(FEISTEL_MIN) / math.log(float(radix))))
        self.maxLen = (math.floor((192 / math.log2(float(radix)))))

        keyLen = len(self.key)

        # Check if the key is 128, 192, or 256 bits = 16, 24, or 32 bytes
        if (keyLen != 16) and (keyLen != 24) and (keyLen != 32):
            raise ValueError("key length is " + str(keyLen) + " but must be 128, 192, or 256 bits")

        # While FF3 allows radices in [2, 2^16], there is a practical limit to 36 (alphanumeric) because the
        # int supports up to base 36.
        if (radix < 2) or (radix > MAX_RADIX):
            raise ValueError("radix must be between 2 and 36, inclusive")

        # Make sure 2 <= minLength <= maxLength < 2*floor(log base radix of 2^96) is satisfied
        if (self.minLen < 2) or (self.maxLen < self.minLen) or (float(self.maxLen) > (192 / math.log2(float(radix)))):
            raise ValueError("minLen or maxLen invalid, adjust your radix")

        # aes.NewCipher automatically returns the correct block based on the length of the key passed in
        # Always use the reversed key since Encrypt and Decrypt call ciph expecting that

        self.aesBlock = AES.AESCipher(reverseString(self.key))

    def encrypt(self, plaintext):
        return self.encryptWithTweak(plaintext, self.tweak)

    """
    Fiestel structure

            u length |  v length

            A block  |  B block

                C = modulo function

            B' <- C    | A' <- B


    Steps:

    Let u = [n/2]
    Let v = n - u
    Let A = X[1..u]
    Let B = X[u+1,n]
    Let T(L) = T[0..31] and T(R) = T[32..63]
    for i <- 0 to 6 do
        If is even, let m = u and W = T(R) Else let m = v and W = T(L)
        Let P = REV([NUM<radix>(Rev(B))]^12 || W ⊗ REV(i^4)
        Let Y = CIPH(P)
        Let y = NUM<2>(REV(Y))
        Let c = (NUM<radix>(REV(A)) + y) mod radix^m
        Let C = REV(STR<radix>^m(c))
        Let A = B
        Let B = C
    end for
    Return A || B

    * Where REV(X) reverses the order of characters in the character string X

    See spec and examples:

    https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38Gr1-draft.pdf
    https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/FF3samples.pdf
    """

    # EncryptWithTweak allows a parameter tweak instead of the current Cipher's tweak

    def encryptWithTweak(self, plaintext, tweak):
        tweakBytes = bytes.fromhex(tweak)

        n = len(plaintext)

        # Check if message length is within minLength and maxLength bounds
        # TODO: when n==c.maxLen, it breaks. For now, changing the
        # input check to >= instead of only >

        if (n < self.minLen) or (n >= self.maxLen):
            raise ValueError("message length is not within min and max bounds")

        # Make sure the given the length of tweak in bits is 64
        if len(tweakBytes) != TWEAK_LEN:
            raise ValueError("tweak length invalid: tweak must be 8 bytes, or 64 bits")

        # Check if the plaintext message is formatted in the current radix
        x = int(plaintext, self.radix)
        if x == 0:
            print(plaintext + ': ' + str(self.radix))
            raise ValueError("plaintext string is not within base/radix")

        # Calculate split point
        u = (math.ceil(float(n) / 2))
        v = n - u

        # Split the message
        A = plaintext[:u]
        B = plaintext[u:]

        # Split the tweak
        Tl = tweakBytes[:HALF_TWEAK_LEN]
        Tr = tweakBytes[HALF_TWEAK_LEN:]

        logging.debug("Tweak: " + tweak)
        logging.debug(tweakBytes)
        # hexdump(tweakBytes)

        # P is always 16 bytes
        P = bytearray(BLOCK_SIZE)

        # Pre-calculate the modulus since it's only one of 2 values,
        # depending on whether i is even or odd

        modU = self.radix ** u
        modV = self.radix ** v
        logging.debug("modU: " + str(modU) + " modV: " + str(modV))

        # Main Feistel Round, 8 times

        for i in range(NUM_ROUNDS):
            logging.debug("-------- Round " + str(i))
            # Determine alternating Feistel round side
            if i % 2 == 0:
                m = u
                W = Tr
            else:
                m = v
                W = Tl

            # Calculate P by XORing W, i into the first 4 bytes of P
            # i only requires 1 byte, rest are 0 padding bytes
            # Anything XOR 0 is itself, so only need to XOR the last byte

            P[0] = W[0]
            P[1] = W[1]
            P[2] = W[2]
            P[3] = W[3] ^ int(i)

            # The remaining 12 bytes of P are for rev(B) with padding

            numB = reverseString(B)
            numBBytes = int(numB, self.radix).to_bytes(12, "big")

            logging.debug("B: " + str(B) + " numB:" + numB + " numBBytes:" + numBBytes.hex())

            P[BLOCK_SIZE-len(numBBytes):] = numBBytes

            # print("P:    ", end='')
            # hexdump(P)

            # Calculate S by operating on P in place
            revP = reverseString(P)

            # print("revP: ", end='')
            # hexdump(revP)

            # P is fixed-length 16 bytes
            revP = self.aesBlock.encrypt(bytes(revP))

            S = reverseString(revP)
            # print("S:    ", end='')
            # hexdump(S)

            y = int.from_bytes(S, byteorder='big')

            # Calculate c
            c = int(reverseString(A), self.radix)

            if c == 0:
                raise ValueError("string A is not within base/radix")

            c = c + y

            if i % 2 == 0:
                c = c % modU
            else:
                c = c % modV

            logging.debug("m: " + str(m) + " A: " + A + " c: " + str(c) + " y:" + str(y))

            C = base_repr(c, base=self.radix)

            # Need to pad the text with leading 0s first to make sure it's the correct length
            while len(C) < int(m):
                C = "0" + C

            C = reverseString(C)

            # Final steps
            A = B
            B = C

            logging.debug("A: " + A + "   B: " + B)

        return A + B

    def decrypt(self, ciphertext):
        return self.decryptWithTweak(ciphertext, self.tweak)

    def decryptWithTweak(self, ciphertext, tweak):
        tweakBytes = bytes.fromhex(tweak)

        n = len(ciphertext)

        # Check if message length is within minLength and maxLength bounds
        # TODO: when n==c.maxLen, it breaks. For now, check >= instead of only >

        if (n < self.minLen) or (n >= self.maxLen):
            raise ValueError("message length is not within min and max bounds")

        # Make sure the given the length of tweak in bits is 64
        if len(tweakBytes) != TWEAK_LEN:
            raise ValueError("tweak length invalid: tweak must be 8 bytes, or 64 bits")

        # Check if the ciphertext message is formatted in the current radix
        x = int(ciphertext, self.radix)
        if x == 0:
            print(ciphertext + ': ' + str(self.radix))
            raise ValueError("ciphertext string is not within base/radix")

        # Calculate split point
        u = (math.ceil(float(n) / 2))
        v = n - u

        # Split the message
        A = ciphertext[:u]
        B = ciphertext[u:]

        # Split the tweak
        Tl = tweakBytes[:HALF_TWEAK_LEN]
        Tr = tweakBytes[HALF_TWEAK_LEN:]

        logging.debug("Tweak: " + tweak)
        logging.debug(tweakBytes)
        # hexdump(tweakBytes)

        # P is always 16 bytes
        P = bytearray(BLOCK_SIZE)

        # Pre-calculate the modulus since it's only one of 2 values,
        # depending on whether i is even or odd

        modU = self.radix ** u
        modV = self.radix ** v
        logging.debug("modU: " + str(modU) + " modV: " + str(modV))

        # Main Feistel Round, 8 times

        for i in reversed(range(NUM_ROUNDS)):

            logging.debug("-------- Round " + str(i))
            # Determine alternating Feistel round side
            if i % 2 == 0:
                m = u
                W = Tr
            else:
                m = v
                W = Tl

            # Calculate P by XORing W, i into the first 4 bytes of P
            # i only requires 1 byte, rest are 0 padding bytes
            # Anything XOR 0 is itself, so only need to XOR the last byte

            P[0] = W[0]
            P[1] = W[1]
            P[2] = W[2]
            P[3] = W[3] ^ int(i)

            # The remaining 12 bytes of P are for rev(A) with padding

            numA = reverseString(A)
            numABytes = int(numA, self.radix).to_bytes(12, "big")

            logging.debug("A: " + str(A) + " numA:" + numA + " numABytes:" + numABytes.hex())

            P[BLOCK_SIZE-len(numABytes):] = numABytes

            # print("P:    ", end='')
            # hexdump(P)

            # Calculate S by operating on P in place
            revP = reverseString(P)

            # print("revP: ", end='')
            # hexdump(revP)

            # P is fixed-length 16 bytes
            revP = self.aesBlock.encrypt(bytes(revP))

            S = reverseString(revP)
            # print("S:    ", end='')
            # hexdump(S)

            y = int.from_bytes(S, byteorder='big')

            # Calculate c
            c = int(reverseString(B), self.radix)

            if c == 0:
                raise ValueError("string A is not within base/radix")

            c = c - y

            if i % 2 == 0:
                c = c % modU
            else:
                c = c % modV

            logging.debug("m: " + str(m) + " A: " + A + " c: " + str(c) + " y:" + str(y))

            C = base_repr(c, base=self.radix)

            # Need to pad the text with leading 0s first to make sure it's the correct length
            while len(C) < int(m):
                C = "0" + C

            C = reverseString(C)

            # Final steps
            B = A
            A = C

            logging.debug("A: " + A + "   B: " + B)

        return A + B


'''
numpy's base_repr has been adjusted here to provide lower-case alphabet for 10..36 
'''


def base_repr(number, base=2, padding=0):
    """
    Return a string representation of a number in the given base system.
    Parameters
    ----------
    number : int
        The value to convert. Positive and negative values are handled.
    base : int, optional
        Convert `number` to the `base` number system. The valid range is 2-36,
        the default value is 2.
    padding : int, optional
        Number of zeros padded on the left. Default is 0 (no padding).
    Returns
    -------
    out : str
        String representation of `number` in `base` system.
    See Also
    --------
    binary_repr : Faster version of `base_repr` for base 2.
    Examples
    --------
    >>> np.base_repr(5)
    '101'
    >>> np.base_repr(6, 5)
    '11'
    >>> np.base_repr(7, base=5, padding=3)
    '00012'
    >>> np.base_repr(10, base=16)
    'A'
    >>> np.base_repr(32, base=16)
    '20'
    """
    digits = '0123456789abcdefghijklmnopqrstuvwxyz'
    if base > len(digits):
        raise ValueError("Bases greater than 36 not handled in base_repr.")
    elif base < 2:
        raise ValueError("Bases less than 2 not handled in base_repr.")

    num = abs(number)
    res = []
    while num:
        res.append(digits[num % base])
        num //= base
    if padding:
        res.append('0' * padding)
    if number < 0:
        res.append('-')
    return ''.join(reversed(res or '0'))


