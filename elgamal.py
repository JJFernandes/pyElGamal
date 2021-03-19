#!/usr/bin/python3

# using Cryptodome to get access to getPrime() and inverse()
# might as well use the getRandomRange() too instead of importing random.randint()
from Crypto.Util import number


class Elgamal():


	def __init__(self, nbits):
		self.privatekey, self.publickey = self.keygen(nbits)


	class PublicKey():
		def __init__(self, p, g, B):
			self.p = p # modulus
			self.g = g # generator
			self.B = B # bob's public key

		def get(self):
			return self.p, self.g, self.B

		def __str__(self):
			return f'PublicKey[ p = {self.p}, g = {self.g}, B = {self.B} ]\n'


	class PrivateKey():
		def __init__(self, p, b):
			self.p = p # modulus
			self.b = b # bob's private key

		def get(self):
			return (self.p, self.b)

		def __str__(self):
			return f'PrivateKey [ p = {self.p}, b = {self.b} ]\n'


	# recursive modular exponentiation
	def modexp(self, base, exp, mod):
		
		if base == 0:
			return 0

		if exp == 0:
			return 1

		if exp % 2 == 1: # exp is odd
			return self.modexp(base, exp-1, mod) * base % mod

		else: # exp is even
			r = self.modexp(base, exp//2, mod) % mod
			return r * r


	# generate private and public keys
	def keygen(self, nbits):
		
		p = number.getPrime(nbits)
		g = number.getRandomRange(2, p)

		b = number.getRandomRange(1, p-1) # bob's private key
		B = self.modexp(g, b, p) # bob's public key

		kpr = self.PrivateKey(p, b)
		kpb = self.PublicKey(p, g, B)

		return kpr, kpb


	def encrypt_msg(self, msg):

		enc_msg = []

		for i in range(0, len(msg)): 
			enc_msg.append(msg[i]) 

		p, g, B = self.publickey.get()

		a = number.getRandomRange(1, p-1) # alice's private key 

		A = self.modexp(g, a, p) # alice's public key 
		s = self.modexp(B, a, p) # shared secret

		for i in range(0, len(enc_msg)): 
			enc_msg[i] = ord(enc_msg[i]) * s % p

		return A, enc_msg


	def decrypt_msg(self, A, enc_msg):
		
		dec_msg = []

		for i in range(0, len(enc_msg)): 
			dec_msg.append(enc_msg[i])

		p, b = self.privatekey.get()

		# B = g^b mod p // A = g^a mod p
		# s = B^a mod p -> (g^b)^a mod p // s = A^b mod p -> (g^a)^b mod p
		s = self.modexp(A, b, p) # retrieve shared secret
		s_inv = number.inverse(s, p) # modular multiplicative inverse

		for i in range(0, len(dec_msg)):
			dec_msg[i] = chr(dec_msg[i] * s_inv % p)

		return dec_msg


	def encrypt_num(self, num):

		p, g, B = self.publickey.get()

		a = number.getRandomRange(1, p-1) # alice's private key 

		A = self.modexp(g, a, p) # alice's public key 
		s = self.modexp(B, a, p) # shared secret

		enc_num = (int(hex(num), 16)) * s % p

		return A, enc_num


	def decrypt_num(self, A, enc_num):

		p, b = self.privatekey.get()

		# B = g^b mod p // A = g^a mod p
		# s = B^a mod p -> (g^b)^a mod p // s = A^b mod p -> (g^a)^b mod p
		s = self.modexp(A, b, p) # retrieve shared secret
		s_inv = number.inverse(s, p) # modular multiplicative inverse

		dec_num = enc_num * s_inv % p

		return dec_num


	def homomorphic_mult(self, enc_num1, A1, enc_num2, A2):

		p, g, B = self.publickey.get()

		homo_A = (A1 * A2) % p
		homo_product = (enc_num1 * enc_num2) % p

		return homo_A, homo_product




elgamal = Elgamal(256) #setting a larger keysize takes too long
print()
print(elgamal.privatekey)
print(elgamal.publickey)


print("\nElGamal for String Messages\n------------------------------------------------")
message = input("Enter message: ")

A, enc_msg = elgamal.encrypt_msg(message)
print(f'\nA = {A}\n')
print(f'enc_msg = {enc_msg}\n')

dec_msg = elgamal.decrypt_msg(A, enc_msg)
print(f'dec_msg = {dec_msg}\n')
print(f'dec_msg_joined = {"".join(dec_msg)}\n')



print("\nElGamal for Int Values and Homomorphic Multiplication\n------------------------------------------------")

num1 = int(input("Enter number 1: "))
num2 = int(input("Enter number 2: "))

real_product = num1 * num2
print(f'\nreal_product = {real_product}\n')
A_real, enc_product_real = elgamal.encrypt_num(real_product)
print(f'A_real = {A_real}\n')
print(f'enc_product_real = {enc_product_real}\n')
dec_product_real = elgamal.decrypt_num(A_real, enc_product_real)
print(f'dec_product_real = {dec_product_real}\n\n')

A1, enc_num1 = elgamal.encrypt_num(num1)
A2, enc_num2 = elgamal.encrypt_num(num2)
print(f'A1 = {A1}\n')
print(f'enc_num1 = {enc_num1}\n')
print(f'A2 = {A2}\n')
print(f'enc_num2 = {enc_num2}\n')
homo_A, enc_homo_product = elgamal.homomorphic_mult(enc_num1, A1, enc_num2, A2)
print(f'enc_homo_product = {enc_homo_product}\n')
dec_homo_product = elgamal.decrypt_num(homo_A, enc_homo_product)
print(f'dec_homo_product = {dec_homo_product}\n')



