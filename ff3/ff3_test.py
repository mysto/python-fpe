'''

SPDX-Copyright: Copyright (c) Schoening Consulting, LLC
SPDX-License-Identifier: Apache-2.0
Copyright 2021 Schoening Consulting, LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.

'''

import unittest
from ff3 import FF3Cipher, base_conv_r

# Test vectors taken from here: http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/FF3samples.pdf

# TODO: NIST announced in SP 800 38G Revision 1, the "the tweak parameter is reduced to 56 bits, in a 
# manner that was subsequently developed by the designers of the method."

testVector = [
	# AES-128
	{ 
		"radix" : 10, 
		"key" : "EF4359D8D580AA4F7F036D6F04FC6A94",
		"tweak" : "D8E7920AFA330A73",
		"plaintext" : "890121234567890000",
		"ciphertext" : "750918814058654607"
	},
	{
		"radix" : 10,
		"key" : "EF4359D8D580AA4F7F036D6F04FC6A94",
		"tweak" : "9A768A92F60E12D8",
		"plaintext" : "890121234567890000",
		"ciphertext" : "018989839189395384",
	},
	{
		"radix" : 10,
		"key" : "EF4359D8D580AA4F7F036D6F04FC6A94",
		"tweak" : "D8E7920AFA330A73",
		"plaintext" : "89012123456789000000789000000",
		"ciphertext" : "48598367162252569629397416226",
	},
	{
		"radix" : 10, 
		"key" : "EF4359D8D580AA4F7F036D6F04FC6A94",
		"tweak" : "0000000000000000",
		"plaintext" : "89012123456789000000789000000",
		"ciphertext" : "34695224821734535122613701434",
	},
	{
		"radix" : 26, 
		"key" : "EF4359D8D580AA4F7F036D6F04FC6A94",
		"tweak" : "9A768A92F60E12D8",
		"plaintext" : "0123456789abcdefghi",
		"ciphertext" : "g2pk40i992fn20cjakb",
	},

	# AES - 192
	{
		"radix" : 10,
		"key" : "EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6",
		"tweak" : "D8E7920AFA330A73",
		"plaintext" : "890121234567890000",
		"ciphertext" : "646965393875028755",
	},
	{
		"radix" : 10,
		"key" : "EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6",
		"tweak" : "9A768A92F60E12D8",
		"plaintext" : "890121234567890000",
		"ciphertext" : "961610514491424446",
	},
	{
		"radix" : 10,
		"key" : "EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6",
		"tweak" : "D8E7920AFA330A73",
		"plaintext" : "89012123456789000000789000000",
		"ciphertext" : "53048884065350204541786380807",
	},
	{
		"radix" : 10,
		"key" : "EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6",
		"tweak" : "0000000000000000",
		"plaintext" : "89012123456789000000789000000",
		"ciphertext" : "98083802678820389295041483512",
	},
	{
		"radix" : 26,
		"key" : "EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6",
		"tweak" : "9A768A92F60E12D8",
		"plaintext" : "0123456789abcdefghi",
		"ciphertext": "i0ihe2jfj7a9opf9p88",
	},

	# AES - 256
	{
		"radix" : 10,
		"key" : "EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C",
		"tweak" :"D8E7920AFA330A73",
		"plaintext" : "890121234567890000",
		"ciphertext" : "922011205562777495",
	},
	{
		"radix" : 10,
		"key" : "EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C",
		"tweak" :"9A768A92F60E12D8",
		"plaintext" : "890121234567890000",
		"ciphertext" : "504149865578056140",
	},
	{
		"radix" : 10,
		"key" : "EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C",
		"tweak" :"D8E7920AFA330A73",
		"plaintext" : "89012123456789000000789000000",
		"ciphertext" : "04344343235792599165734622699",
	},
	{
		"radix" : 10,
		"key" : "EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C",
		"tweak" :"0000000000000000",
		"plaintext" : "89012123456789000000789000000",
		"ciphertext" : "30859239999374053872365555822",
	},
	{
		"radix" : 26,
		"key" : "EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C",
		"tweak" :"9A768A92F60E12D8",
		"plaintext" : "0123456789abcdefghi",
		"ciphertext" : "p0b2godfja9bhb7bk38",
	}
]

class TestFF3(unittest.TestCase):

	def test_base_repr(self):
		self.assertEqual(base_conv_r(5)[::-1], '101')
		self.assertEqual(base_conv_r(6,5)[::-1], '11')
		self.assertEqual(base_conv_r(7,5,5)[::-1], '00012')
		self.assertEqual(base_conv_r(10,16)[::-1], 'a')
		self.assertEqual(base_conv_r(32,16)[::-1], '20')

	def test_encrypt_all(self):
		for i in range(15):
			with self.subTest(vector=i):
				c = FF3Cipher(testVector[i]['radix'], testVector[i]['key'], testVector[i]['tweak'])
				s = c.encrypt(testVector[i]['plaintext'])
				self.assertEqual(s, testVector[i]['ciphertext'])

	def test_decrypt_all(self):
		for i in range(15):
			with self.subTest(vector=i):
				c = FF3Cipher(testVector[i]['radix'], testVector[i]['key'], testVector[i]['tweak'])
				s = c.decrypt(testVector[i]['ciphertext'])
				self.assertEqual(s, testVector[i]['plaintext'])

if __name__ == '__main__':
	unittest.main()
