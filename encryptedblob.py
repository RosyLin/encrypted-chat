import base64
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
import imexceptions
from Crypto.Hash import HMAC, SHA256


class EncryptedBlob:

    # the constructor
    def __init__(self, plaintext=None, confkey=None, authkey=None): 
        self.plaintext = plaintext
        self.ivBase64 = None
        self.ciphertextBase64 = None
        self.macBase64 = None

        if plaintext is not None:
            self.ivBase64, self.ciphertextBase64, self.macBase64 = self.encryptThenMAC(confkey, authkey, plaintext)



    # encrypts the plaintext and adds a SHA256-based HMAC
    # using an encrypt-then-MAC solution
    def encryptThenMAC(self,confkey,authkey,plaintext):
        # TODO: MODIFY THE CODE BELOW TO ACTUALLY ENCRYPT 
        # AND GENERATE A SHA256-BASED HMAC BASED ON THE 
        # confkey AND authkey
        plaintextPadded = pad(bytes(plaintext,'utf-8'),16) 

        cipher = AES.new(confkey, AES.MODE_CBC)
        iv = cipher.iv
        ciphertext = cipher.encrypt(plaintextPadded)
                                            
        mac = HMAC.new(authkey, digestmod=SHA256)
        mac.update(ciphertext)
        d = mac.digest()

        # DON'T CHANGE THE BELOW.
        ivBase64 = base64.b64encode(iv).decode("utf-8") 
        ciphertextBase64 = base64.b64encode(ciphertext).decode("utf-8") 
        macBase64 = base64.b64encode(d).decode("utf-8") 
        return ivBase64, ciphertextBase64, macBase64


    def decryptAndVerify(self,confkey,authkey,ivBase64,ciphertextBase64,macBase64):
        iv = base64.b64decode(ivBase64)
        ciphertext = base64.b64decode(ciphertextBase64)
        mac = base64.b64decode(macBase64)
        
        # TODO: MODIFY THE CODE BELOW TO ACTUALLY DECRYPT
        # IF IT DOESN'T DECRYPT, YOU NEED TO RAISE A 
        # FailedDecryptionError EXCEPTION

        # TODO: hint: in encryptThenMAC, I padded the plaintext.  You'll
        # need to unpad it.
        # See https://pycryptodome.readthedocs.io/en/v3.11.0/src/util/util.html#crypto-util-padding-module
        try:
            cipher = AES.new(confkey,AES.MODE_CBC, iv)
            decrypttext = cipher.decrypt(ciphertext) #, AES.block_size)     
        except imexceptions.FailedDecryptionError:
            print("Incorrect decrytion")      
       
        decryptUnpad = unpad(decrypttext,16) 
        self.plaintext = decryptUnpad.decode("utf-8")

        # TODO: DON'T FORGET TO VERIFY THE MAC!!!
        # IF IT DOESN'T VERIFY, YOU NEED TO RAISE A
        # FailedAuthenticationError EXCEPTION

        v = HMAC.new(authkey, digestmod=SHA256)
        v.update(ciphertext)
        h = v.digest()
        
        if h != mac:
                throw imexceptions.FailedAuthenticationError("ruh oh!")

            



        
        

        return self.plaintext
