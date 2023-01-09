import tools
import os
from Crypto.Cipher import AES,DES3,Blowfish
from Crypto.Util.Padding import pad
from struct import pack
from Crypto.Random import get_random_bytes

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

def aesCipher(aesKey):
    aes_cipher = AES.new(aesKey, AES.MODE_EAX)
    nonce = aes_cipher.nonce
    data = b"trying the whole encryption thing out"
    encrypted_data, tag = aes_cipher.encrypt_and_digest(data)
    return encrypted_data,nonce,tag

def aesCipherDecrypt(aesKey, nonce, tag, encrypted_data):
    aes_cipher = AES.new(aesKey, AES.MODE_EAX, nonce)
    decrypted_data = aes_cipher.decrypt_and_verify(encrypted_data, tag)
    print(decrypted_data)
    

def BlowFish_encrypt(blowfishKey):
    data = b"hello world"
    blowfish_cipher = Blowfish.new(blowfishKey, Blowfish.MODE_EAX)
    nonce = blowfish_cipher.nonce
    secret_data = blowfish_cipher.encrypt(data)
    return secret_data, nonce

def BlowFish_decrypt(blowfishKey,data,nonce):
    blowfish_cipher = Blowfish.new(blowfishKey, Blowfish.MODE_EAX,nonce)
    decrypted_data = blowfish_cipher.decrypt(data)
    print(decrypted_data)

def DES_encrypt(desKey):
    data = b"hello world welcome to my playground"
    DES_cipher = DES3.new(desKey, DES3.MODE_EAX)
    nonce = DES_cipher.nonce
    secret_data = DES_cipher.encrypt(data)
    return secret_data, nonce

def DES_decrypt(desKey,data,nonce):
    DES_cipher = DES3.new(desKey, DES3.MODE_EAX,nonce)
    decrypted_data = DES_cipher.decrypt(data)
    print(decrypted_data)
    
aesKey = get_random_bytes(16)
data, nonce =DES_encrypt(aesKey)
DES_decrypt(aesKey,data,nonce)
