#!/usr/bin/python3

from src import elgamal

elg = elgamal.Elgamal(256) #setting a larger keysize takes too long
print()
print(elg.privatekey)
print(elg.publickey)


print("\nElGamal for String Messages\n------------------------------------------------")
message = input("Enter message: ")

A, enc_msg = elg.encrypt_msg(message)
print(f'\nA = {A}\n')
print(f'enc_msg = {enc_msg}\n')

dec_msg = elg.decrypt_msg(A, enc_msg)
print(f'dec_msg = {dec_msg}\n')
print(f'dec_msg_joined = {"".join(dec_msg)}\n')


print("\nElGamal for Int Values and Homomorphic Multiplication\n------------------------------------------------")

num1 = int(input("Enter number 1: "))
num2 = int(input("Enter number 2: "))

real_product = num1 * num2
print(f'\nreal_product = {real_product}\n')
A_real, enc_product_real = elg.encrypt_num(real_product)
print(f'A_real = {A_real}\n')
print(f'enc_product_real = {enc_product_real}\n')
dec_product_real = elg.decrypt_num(A_real, enc_product_real)
print(f'dec_product_real = {dec_product_real}\n\n')

A1, enc_num1 = elg.encrypt_num(num1)
A2, enc_num2 = elg.encrypt_num(num2)
print(f'A1 = {A1}\n')
print(f'enc_num1 = {enc_num1}\n')
print(f'A2 = {A2}\n')
print(f'enc_num2 = {enc_num2}\n')
homo_A, enc_homo_product = elg.homomorphic_mult(enc_num1, A1, enc_num2, A2)
print(f'enc_homo_product = {enc_homo_product}\n')
dec_homo_product = elg.decrypt_num(homo_A, enc_homo_product)
print(f'dec_homo_product = {dec_homo_product}\n')