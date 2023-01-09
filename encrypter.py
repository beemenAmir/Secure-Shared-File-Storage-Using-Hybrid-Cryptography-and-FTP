import tools
import os
from Crypto.Cipher import AES,DES3,Blowfish
from Crypto.Util.Padding import pad
from struct import pack
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


def RSAEncryption(data):
	with open('./rsa/public.pem', 'rb') as f:
		pubkey= f.read()
	rsakey = RSA.importKey(pubkey)
	rsacipher = PKCS1_OAEP.new(rsakey)
	secret_data = rsacipher.encrypt(data)
	target_file = open("raw_data/store_in_me.enc","wb")
	target_file.write(secret_data)
	target_file.close()



def aesCipher(filename,aesKey):
	aes_cipher = AES.new(aesKey,AES.MODE_EAX)
	nonce = aes_cipher.nonce
	source_filename = 'files/' + filename
	target_filename = 'encrypted/' + filename
	file = open(source_filename,'rb')
	target_file = open(target_filename,'wb')
	raw= b""
	for line in file:
		raw = raw + line
	secret_data, tag = aes_cipher.encrypt_and_digest(raw)
	target_file.write(nonce) #16 bytes of data
	target_file.write(tag) #16 bytes of data
	target_file.write(secret_data) #encrypted data
	file.close()
	target_file.close()

def TripdesCipher(filename,desKey):
	DES_cipher = DES3.new(desKey, DES3.MODE_EAX)
	nonce = DES_cipher.nonce
	source_filename = 'files/' + filename
	target_filename = 'encrypted/' + filename
	file = open(source_filename,'rb')
	target_file = open(target_filename,'wb')
	raw= b""
	for line in file:
		raw = raw + line
	secret_data = DES_cipher.encrypt(raw)
	target_file.write(nonce)
	target_file.write(secret_data)
	file.close()
	target_file.close()
def blowfishCipher(filename,blowfishKey):
	blowfish_cipher = Blowfish.new(blowfishKey, Blowfish.MODE_EAX)
	nonce = blowfish_cipher.nonce
	source_filename = 'files/' + filename
	target_filename = 'encrypted/' + filename
	file = open(source_filename,'rb')
	target_file = open(target_filename,'wb')
	raw= b""
	for line in file:
		raw = raw + line
	secret_data = blowfish_cipher.encrypt(raw)
	target_file.write(nonce)
	target_file.write(secret_data)
	file.close()
	target_file.close()
def encrypter():
	tools.empty_folder('key')
	tools.empty_folder('encrypted')
	AESKey = get_random_bytes(16)
	DESKey = get_random_bytes(16)
	BlowFishKey = get_random_bytes(16)
	files = sorted(tools.list_dir('files'))
	for index in range(0,len(files)):
		if index%3 == 0:
			aesCipher(files[index],AESKey)
		elif index%3 == 1:
			TripdesCipher(files[index],DESKey)
		else:
			blowfishCipher(files[index],BlowFishKey)
	secret_information = (AESKey)+b":::::"+(DESKey)+b":::::"+(BlowFishKey)
	RSAEncryption(secret_information)
	tools.empty_folder('files')