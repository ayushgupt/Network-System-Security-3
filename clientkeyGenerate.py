from Crypto.PublicKey import RSA
from Crypto import Random

def createkey(privfile, pubfile,clientid):
    random_generator = Random.new().read
    key = RSA.generate(4096, random_generator)
    secret_code = "bipul123"
    print("Initial calculation")
    print(key)
    print(key.publickey())
    #print('1')
    privHandle = open(privfile, 'wb')
    privHandle.write(key.exportKey(format='PEM',passphrase=secret_code, pkcs=8))#, protection="scryptAndAES128-CBC"))
    privHandle.close()
    #print('2')
    pubHandle = open(pubfile, 'wb')
    pubHandle.write(key.publickey().exportKey(format='PEM'))
    pubHandle.close()
    #print('3')
    pubfile = 'PUBLIC_DIR/'+clientid+'_publickey.bin'
    pubHandle = open(pubfile, 'wb')
    pubHandle.write(key.publickey().exportKey(format='PEM'))
    pubHandle.close()

priv_key_file = 'client1_keys/privatekey.bin'
pub_key_file ='client1_keys/publickey.bin'
clientid = '1000'
createkey(privfile= priv_key_file, pubfile=pub_key_file,clientid=clientid)

