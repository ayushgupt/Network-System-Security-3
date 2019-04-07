from Crypto.PublicKey import RSA
from Crypto import Random

def createkey(privfile, pubfile):
    random_generator = Random.new().read
    key = RSA.generate(1024, random_generator)
    secret_code = "bipul123"
    print("Initial calculation")
    print(key)
    print(key.publickey())

    privHandle = open(privfile, 'wb')
    privHandle.write(key.exportKey(format='PEM',passphrase=secret_code, pkcs=8))#, protection="scryptAndAES128-CBC"))
    privHandle.close()

    pubHandle = open(pubfile, 'wb')
    pubHandle.write(key.publickey().exportKey(format='PEM'))
    pubHandle.close()

    pubfile = 'PUBLIC_DIR/' + clientid + '_publickey.bin'
    pubHandle = open(pubfile, 'wb')
    pubHandle.write(key.publickey().exportKey(format='PEM'))
    pubHandle.close()

priv_key_file = 'server_keys/privatekey.bin'
pub_key_file ='server_keys/publickey.bin'
clientid = 'server'

createkey(privfile= priv_key_file, pubfile=pub_key_file)
