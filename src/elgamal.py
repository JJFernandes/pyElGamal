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
