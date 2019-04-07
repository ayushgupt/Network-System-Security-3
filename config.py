server = {
    'ip': '127.0.0.1',
    'port': 9999,
    'ekey': 'server_keys/publickey.bin',
    'dkey': 'server_keys/privatekey.bin'
}

client = {
    1: {
        'id' : '1000',
        'ip': '127.0.0.1',
        'port': 5555,
        'ekey': 'client1_keys/publickey.bin',
        'dkey': 'client1_keys/privatekey.bin'
    },
    2: {
        'id' : '2000',
        'ip': '127.0.0.1',
        'port': 4444,
        'ekey': 'client2_keys/publickey.bin',
        'dkey': 'client2_keys/privatekey.bin'
    }
}

public_dir = 'PUBLIC_DIR/'

BUFFER_SIZE = 2048

import base64

from Crypto import Random
from Crypto.Cipher import AES

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[0:-ord(s[-1])]

class AESCipher:

    def __init__( self, key ):
        self.key = key

    def encrypt( self, raw ):
        raw = pad(raw)
        iv = Random.new().read( AES.block_size )
        cipher = AES.new( self.key, AES.MODE_CBC, iv )
        return base64.b64encode( iv + cipher.encrypt( raw ) )

    def decrypt( self, enc ):
        enc = base64.b64decode(enc)
        iv = enc[:16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv )
        return unpad(cipher.decrypt( enc[16:] ))


cipher = AESCipher('mysecretpassword')


