import aes
import ecdhe
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib
from base64 import b64decode
from base64 import b64encode
from Cryptodome.Util.Padding import pad, unpad

"""ecc = ecdhe.ECCKeyGenerator(curve=ecdhe.ELLIPTIC_CURVE_160k1)
private_key, public_key = ecc.gen_keypair()
print(public_key[0])


text = aes.AESCipher(str(public_key[0]), str(private_key), "CBC").encrypt("hello world").decode('utf-8')
print(text)
print(aes.AESCipher(str(public_key[0]), str(public_key[1]), "CBC").decrypt(text).decode('utf-8'))"""


#text = aes.AESCipher(str(public_key[0]), str(public_key[1]), "EAX").encrypt("hello world").decode('utf-8')
#print(text)
#print(aes.AESCipher(str(public_key[0]), str(public_key[1]), "EAX").decrypt(text).decode('utf-8'))

"""key = public_key[0]
key = hashlib.sha256(str(key).encode('utf-8')).digest()
data="hello world".encode("utf-8")
cipher = AES.new(key, AES.MODE_CBC)
cipher_text = cipher.encrypt(pad(data, AES.block_size))
iv = cipher.iv
print(cipher_text)
print(iv)



decrypt_cipher = AES.new(key, AES.MODE_CBC, iv)
plain_text = decrypt_cipher.decrypt(cipher_text)
print(plain_text)"""

"""from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

def encrypt_AES_CBC(message, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    padded_message = pad(message.encode(), AES.block_size)
    encrypted_message = cipher.encrypt(padded_message)
    return base64.b64encode(encrypted_message).decode()

def decrypt_AES_CBC(encrypted_message, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    decoded_encrypted_message = base64.b64decode(encrypted_message.encode())
    decrypted_message = cipher.decrypt(decoded_encrypted_message)
    return unpad(decrypted_message, AES.block_size).decode()

# Example usage
key = hashlib.sha256(str(public_key[0]).encode('utf-8')).digest()
iv = hashlib.md5(str(public_key[1]).encode('utf-8')).digest()
message = 'Secret message'

encrypted_message = encrypt_AES_CBC(message, key, iv)
print(f'Encrypted message: {encrypted_message}')

decrypted_message = decrypt_AES_CBC(encrypted_message, key, iv)
print(f'Decrypted message: {decrypted_message}')"""
# (ECB, CFB або OFB)."
file_name =  "rusya.csv"
with open(file_name, "rb") as f:
    plain_text = f.read()

passphrase = "rusya"
encrypted_text = aes.AESCipher(str(passphrase), str(passphrase), "CBC").decrypt(plain_text).decode('utf-8')
print(encrypted_text)
with open(f"{file_name[:-3]}_sec.csv", "wb") as f:
    f.write(encrypted_text.encode())