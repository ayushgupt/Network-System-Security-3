
import config
import socket, base64
import time

from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
import datetime
#print datetime.datetime.utcnow()

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
server_dkey = getDecryptkey(config.server['dkey'])
print('READ KEY SUCCESS')

host_server = config.server['ip']
port_server = config.server['port']

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
s.bind((host_server,port_server))

s.listen(5)

while True:
    print("GST Server: Waiting for Request")
    # recieved encrypted hash data from client1
    c, addr = s.accept()
    print("GST Server: Got a connection from %s" % str(addr))

    data = c.recv(BUFFER_SIZE)
    print('Step 2:')
    print("Recieved Data ", data)

    # decrpted recieved data from client1
    decoded_data = base64.b64decode(data)
    decrypted_data = PKCS1_OAEP.new(server_dkey).decrypt(decoded_data)

    print("decrypted data ", decrypted_data)
    # read current timestamp
    client_id, recd_hash_doc = decrypted_data.split(msg_delim)
    client_ekey_file = config.public_dir + client_id + '_publickey.bin'
    client_ekey = getEncryptkey(client_ekey_file)

    #timestp = time.timezone
    #timestp = time.gmtime(time.time())
    #timestp=datetime.datetime.utcnow()
    timestp = time.ctime(time.time())
    print('Timestamp value : ', timestp)

    x = recd_hash_doc + msg_delim + str(timestp)
    print(x)
    # hashed hashed file and timestamp
    hash_obj = SHA256.new()#.hexdigest()
    print('New calculated Hash', hash_obj)



    # sign by server on above hashed calculation

    signer_x = PKCS1_v1_5.new(server_dkey)
    signature_x = signer_x.sign(hash_obj)

    print('Signature by server: \n', signature_x)

    message = x + msg_delim + str(signature_x)
    print('Actual message (recd_hash_doc<!>timestamp<!> Hash(recd_hash_doc <!> timestamp)) : ) \n ', message)

    encrypted_b = PKCS1_OAEP.new(client_ekey).encrypt(message)
    final_b = base64.b64encode(encrypted_b)
    print('Sending message: \n', final_b)
    c.send(final_b)
    print(' ')
    print(' ')
