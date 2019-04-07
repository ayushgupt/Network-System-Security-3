import six
import config
import socket, base64, sys
import time

from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

BUFFER_SIZE = config.BUFFER_SIZE

# defining msg reply delimiters
msg_delim = '<!>'

def getEncryptkey(ifile):
    pubHandle = open(ifile, 'rb').read()
    key = RSA.importKey(pubHandle,passphrase=None)
    return key

def getDecryptkey(ifile):
    secret_code = "bipul123"
    privHandle = open(ifile, 'rb').read()
    key = RSA.importKey(privHandle, passphrase=secret_code)
    return key

'''
    READ KEYS
'''
server_ekey = getEncryptkey(config.server['ekey'])
client2_ekey = getEncryptkey(config.server['ekey'])
client2_dkey = getDecryptkey(config.server['dkey'])

host_c = config.client[2]['ip']
port_c = config.client[2]['port']

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
s.bind((host_c,port_c))

s.listen(5)

while True:
    # recieved encrypted hash data from client1
    c, addr = s.accept()
    print("Client2: Got a connection from %s" % str(addr))
    print("Waiting for Message")

    data = c.recv(BUFFER_SIZE)
    print("8. recieved encrypted message from client1\n", data)

    #decrpted recieved data from client1
    decrypted_data = config.cipher.decrypt(data)

    #decoded_data = base64.b64decode(data)
    #decrypted_data = PKCS1_OAEP.new(client2_dkey).decrypt(decoded_data)

    print("9. decrypted data ", decrypted_data)
    # read current timestamp
    filedata, timestmp , recv_msg_signature = decrypted_data.split(msg_delim)

    print('filedata = ',filedata)
    print('recieved timestamp ' ,timestmp)
    print('recieved signature ',recv_msg_signature)



    # hash recieved file data
    hash_doc = SHA256.new(filedata.encode('utf-8')).hexdigest()
    x = hash_doc + msg_delim + timestmp
    hash_obj = SHA256.new()
    print('10. hashed combine hashed file and timestamp\n', hash_obj)

    verifier = PKCS1_v1_5.new(server_ekey)
    sign_status = verifier.verify(hash_obj, recv_msg_signature)

    if not sign_status:
        print(' Signature not verified')
    else:
        print(' Signature is Verified')

    c.send(str(sign_status))


