
import socket,base64,sys
import time

from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
import config

BUFFER_SIZE = config.BUFFER_SIZE

# defining msg  delimiters
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

client1_dkey = getDecryptkey(config.client[1]['dkey'])
client1_ekey = getEncryptkey(config.client[1]['ekey'])

client2_dkey = getDecryptkey(config.client[2]['dkey'])
client2_ekey = getEncryptkey(config.client[2]['ekey'])
my_id = config.client[1]['id']

print('READ KEY SUCCESS')

host_server = config.server['ip']
port_server = config.server['port']
host_c = config.client[2]['ip']
port_c = config.client[2]['port']
'''
    STEP 1: Read document, create hash(document) and send to server.
'''

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host_server, port_server))

with open('mytext', 'r') as myfile:
    filedata=myfile.read().replace('\n', '')
print('Step 1:')
hash_doc = SHA256.new(filedata.encode('utf-8')).hexdigest()

message = my_id + msg_delim + hash_doc
print('Actual message (1000<!>Hash doc',message)

encrypted_msg = PKCS1_OAEP.new(server_ekey).encrypt(message.encode('utf-8'))
message = base64.b64encode(encrypted_msg)

print( 'encrypted hash of originl file data\n' , message)
s.send(message)

data = s.recv(BUFFER_SIZE)
print('Recieved Reply from server: \n' ,data)

decoded_data = base64.b64decode(data)
decrypted_data = PKCS1_OAEP.new(client1_dkey).decrypt(decoded_data)

print('DECRYPTED MSG: \n', decrypted_data)
rec_hash_doc,tstamp,rec_signature = decrypted_data.split(msg_delim)
print('RECEIVED HASH DOC: ', rec_hash_doc)
print('RECEIVED TIMESTAMP: ',tstamp)
print('RECEIVED SIGNATURE: ',rec_signature)


if (rec_hash_doc != hash_doc):
    print(' RECEIVED HASH DOC IS DIFFERENT FROM THE ONE SENT.')
    sys.exit()
else:
    print('Verified HASH Doc received')

print('Verify signature from GST server')
x = rec_hash_doc + msg_delim + tstamp
hash_obj = SHA256.new()
print('Calculated Hash', hash_obj)

verifier = PKCS1_v1_5.new(server_ekey)
sign_status =  verifier.verify(hash_obj,rec_signature)

if not sign_status:
    print('GST Signature not verified')
else:
    print('GST Signature is Verified')




#s.close()


conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
conn.connect((host_c, port_c))


dataForC2 = filedata + msg_delim + tstamp + msg_delim + rec_signature

messageToC2 = config.cipher.encrypt(dataForC2)

#encrypted_dataForC2 = PKCS1_OAEP.new(client2_ekey).encrypt(dataForC2)
#messageToC2 = base64.b64encode(encrypted_dataForC2)


print( '7. encrypted hash of originl file data\n' , messageToC2)
conn.send(messageToC2)


data = conn.recv(BUFFER_SIZE)
print ('decrypted data Received from server: \n' , str(data))

conn.close()








    



