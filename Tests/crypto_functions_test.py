import unittest
import string
import random
from crypto_functions import *
from Crypto import Random
from Crypto.PublicKey import RSA

############################################################################# 
# NOTE: THIS FILE NEEDS TO BE RUN IN THE SAME FOLDER AS crypto_functions.py #
#############################################################################

##
# Generates a random string of length 0-1024
# Used as input for encryption for the purpose of testing encryption/decryption
##
def generate_random_string():
	length = random.randint(0,1024)
	output = ""
	characters = string.printable
	for i in range(length):
		output += random.choice(string.printable)
	return output

class TestCrypto(unittest.TestCase):
	##
	# Test AES encryption and decryption
	# Encrypts and then decrypts a randomly generated string using a randomly generated key
	# Test will pass if the decrypted string is equal to the original string
	# Test 1000 different random inputs
	##
	def test_aes(self):
		for i in range(1000):
			plaintext = generate_random_string()
			key = Random.get_random_bytes(16)
			encrypted = aes_encrypt(plaintext,key)
			decrypted = aes_decrypt(encrypted,key)
			self.assertEqual(plaintext,decrypted)

	def test_rsa(self):
		for i in range(1000):
			plaintext = generate_random_string()
			private_key = RSA.generate(2048)
			public_key = private_key.publickey()
			encrypted = rsa_encrypt(plaintext,public_key)
			decrypted = rsa_decrypt(encrypted,private_key)
			self.assertEqual(plaintext,decrypted)
		

if __name__ == '__main__':
	unittest.main()

