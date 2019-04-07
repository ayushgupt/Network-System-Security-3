# Network-System-Security-3

## serverkeyGenerate.py, clientkeyGenerate.py, clientkeyGenerate2.py
- We use the same paraphrase (bipul123) to generate the private key  
- Ids are server, 1000 and 2000  
- Public Keys are written in PUBLIC_DIR , whereas private keys are written in client1_keys, server_keys and client2_keys  
- Generating RSA object: (RSA.generate(4096, random_generator))  
- Generating Private Key: key.exportKey(format='PEM',passphrase=secret_code, pkcs=8)  
- Generating Public Key: key.publickey().exportKey(format='PEM')  
