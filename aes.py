import hashlib 
from base64 import b64decode
from base64 import b64encode

from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad


class AESCipher:
    def __init__(self, key, iv, mode):
        self.key = hashlib.sha256(key.encode('utf-8')).digest()
        self.iv =  hashlib.md5(iv.encode('utf-8')).digest()
        self.mode = getattr(AES, f"MODE_{mode}")
        

    def encrypt(self, data):
        #iv = get_random_bytes(AES.block_size)
        self.cipher = AES.new(self.key, self.mode, self.iv)
        try:
            data = data.encode('utf-8')
        except Exception:
            pass
        return b64encode(self.iv + self.cipher.encrypt(pad(data, 
            AES.block_size)))
            
    def decrypt(self, data):
        raw = b64decode(data)
        self.cipher = AES.new(self.key, self.mode, raw[:AES.block_size])
        return unpad(self.cipher.decrypt(raw[AES.block_size:]), AES.block_size)


if __name__ == '__main__':
    mode = input("MODE: " )
    print('ENCRYPTION')
    msg = input('Message: ')
    pwd = input('Password: ')
    iv = '53346768628022570227654718852769885576041486309964088668582480759557650996988'
    print('Ciphertext:', AESCipher(pwd, iv, mode).encrypt(msg).decode('utf-8'))

    print('\nDECRYPTION')
    cte = input('Ciphertext: ')
    pwd = input('Password: ')
    print('Message:', AESCipher(pwd, iv, mode).decrypt(cte).decode('utf-8'))