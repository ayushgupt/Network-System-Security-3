# Network-System-Security-3

## serverkeyGenerate.py, clientkeyGenerate.py, clientkeyGenerate2.py
- We use the same paraphrase (bipul123) to generate the private key  
- Ids are server, 1000 and 2000  
- Public Keys are written in PUBLIC_DIR , whereas private keys are written in client1_keys, server_keys and client2_keys  
- Generating RSA object: (RSA.generate(4096, random_generator))  
- Generating Private Key: key.exportKey(format='PEM',passphrase=secret_code, pkcs=8)  
- Generating Public Key: key.publickey().exportKey(format='PEM')  

## Order of Running these files
- First the above 3 scripts should be run to generate the public and private keys
- Then Need to run server.py, then client2.py and finally client1.py

## config.py
- BUFFER SIZES
- Encryption and decryption file paths
- AESCipher (a set secret password for clients and servers to communicate using AES encryption)
- Pad and Unpad functions
## server.py
- Reads the generated encryption(public) and decrytion(private) key from the config which has path to the file generated by generateKey files, also takes in a predecided IP and Port from the config file
- It starts by waiting to recieve data(c) from some address(addr) (of client1)
- Data recieved from client1 is first base64 decoded and then decrypted using server's decryption key
- Decrypted message contains 2 parts "client_id" who sent the document and "recd_hash_doc" that is hash of the recieved document
- Server then adds timestamp calculated from time.ctime and encrypts by using the clients public key from the publicDirectory
- Server now adds its signature(made using its private key) to this (doc_hash+time_stamp), signature is calculated using these lines below
  - hash_obj = SHA256.new()
  - signer_x = PKCS1_v1_5.new(server_dkey)
  - signature_x = signer_x.sign(hash_obj)
- This (doc_hash+time_stamp+signature_x) is the encrypted using client's public key and sent back to client by encoding in base64 format
## client1.py
- Reads the generated encryption(public) and decrytion(private) key from the config which has path to the file generated by generateKey files, also takes in a predecided IP and Port from the config file
- Client sends SHA256 encoded (UTF-8 encoded filedata) to the Server and gets back (hash_doc+tstamp+rec_signature) by decoding Server's message with it's private key
- It firstly verifies whether recieved and sent Hash doc is same
- It then verifies the Server's signature using verifier object made using server's public key
  - hash_obj = SHA256.new()
  - verifier = PKCS1_v1_5.new(server_ekey)
  - sign_status =  verifier.verify(hash_obj,rec_signature)
- Done with all the verification from Server side, now things start with the client2 side
- Client2 is sent [ AES encrypted (filedata + tstamp  + rec_signature) ] by Client1
- Client2 then again tries to verify the signature of server and is able to do so by using server's Public key
- Client1 recieves back the result and just prints it out
## client2.py
- It just recieves message from Client1 and verifies it using server public key
- Then reverts the status back to Client1 for printing

## Some Crypto functions used
- PKCS1_v1_5 is used to make a signature verifier object
  - from Crypto.Signature import PKCS1_v1_5
  - verifier = PKCS1_v1_5.new(server_ekey)
  - sign_status = verifier.verify(hash_obj, recv_msg_signature)
- PKCS1_OAEP is used to use Public and Private keys to encrypt or decrypt using generated keys
  - from Crypto.Cipher import PKCS1_OAEP
  - encrypted_msg = PKCS1_OAEP.new(server_ekey).encrypt(message.encode('utf-8'))
  - decrypted_data = PKCS1_OAEP.new(client1_dkey).decrypt(decoded_data)
- base64 is used to encode or decode data before sending via sockets
  - message = base64.b64encode(encrypted_msg)
  - decoded_data = base64.b64decode(data)
