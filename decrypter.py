import tools
import os
from Crypto.Cipher import AES,DES3,Blowfish
from Crypto.Util.Padding import pad
from struct import pack
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def RSADecrypt():
	with open('./rsa/private.pem', 'rb') as f:
		privekey= f.read()
	rsakey = RSA.importKey(privekey)
	rsacipher = PKCS1_OAEP.new(rsakey)
	target_file = open("raw_data/store_in_me.enc","rb")
	secret_data = b""
	for line in target_file:
		secret_data = secret_data + line
	data = rsacipher.decrypt(secret_data)
	target_file.close()
	return data

def aesCipherDecrypt(filename,aesKey):
	source_filename = 'encrypted/' + filename
	target_filename = 'files/' + filename
	with open(source_filename,'rb') as f:
		nonce = f.read(16)
		tag = f.read(16)
		data = f.read()
		f.close()
	target_file = open(target_filename,'wb')
	
	aes_cipher = AES.new(aesKey, AES.MODE_EAX, nonce)
	decrypted_data = aes_cipher.decrypt_and_verify(data, tag)
	target_file.write(decrypted_data)
	
	target_file.close()
	
def TripleDesCipherDecrypt(filename, desKey):
	source_filename = 'encrypted/' + filename
	target_filename = 'files/' + filename
	with open(source_filename,'rb') as f:
		nonce = f.read(16)
		data = f.read()
		f.close()
	target_file = open(target_filename,'wb')
	DES_cipher = DES3.new(desKey, DES3.MODE_EAX,nonce)
	decrypted_data = DES_cipher.decrypt(data)
	target_file.write(decrypted_data)
	target_file.close()
	
def BlowFishCipherDecrypt(filename,blowfishKey):
	source_filename = 'encrypted/' + filename
	target_filename = 'files/' + filename
	with open(source_filename,'rb') as f:
		nonce = f.read(16)
		data = f.read()
		f.close()
	target_file = open(target_filename,'wb')
	blowfish_cipher = Blowfish.new(blowfishKey, Blowfish.MODE_EAX,nonce)
	decrypted_data = blowfish_cipher.decrypt(data)
	target_file.write(decrypted_data)
	target_file.close()
	
	
def decrypter():
	tools.empty_folder('files')	
	secret_information = RSADecrypt()
	list_information = secret_information.split(b':::::')
	AESKey = list_information[0]
	DESKey = list_information[1]
	BlowFishKey = list_information[2]
	files = sorted(tools.list_dir('encrypted'))
	for index in range(0,len(files)):
		if index%3 == 0:
			aesCipherDecrypt(files[index],AESKey)
		elif index%3 == 1:
			TripleDesCipherDecrypt(files[index],DESKey)
		else:
			BlowFishCipherDecrypt(files[index],BlowFishKey)
		