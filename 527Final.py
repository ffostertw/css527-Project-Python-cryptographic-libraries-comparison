#Kevin Wu' python project.
#527 Final project.
'''
  This project imports three libraries to perform encryption algorithm comparisons: 
    import the PyCrypto library
    import the M2Crypto library
    import the Pydes library
     - specifically  for DES

'''
import time
import os
import sys
import M2Crypto
import base64
import ast

#Code to solve the issue if library.egg is not in a secure directory
#No need to include in Ubuntu OS
#os.environ['PYTHON_EGG_CACHE'] = '/tmp'

encryptionavg = 0
decryptionavg = 0
def printer_me():
    print "Start the 527 Final Project!!"
    print "Encrypt and Decrpt or Hash the 'Plain.txt' in three libraries!"
    print "Algorithms include: "
    print "HMAC, SHA1, RC4, AES-OFB, DSA, RSA, AES, DES."
    print ""

#===================
#  PyCrypto Library
def PyCrypto_AES():
 global encryptionavg
 global decryptionavg
 from Crypto.Cipher import AES
 startTime = time.time()
 encryptor = AES.new(key, AES.MODE_CBC,IV)
 ciphertext = encryptor.encrypt(plainContent)
 totalTime = time.time() - startTime
 encryptionavg += totalTime
 #print totalTime
 print('AES-CBC Encryption: Total time: %.5f seconds' %  totalTime)


 startTime = time.time()
 decryptor = AES.new(key, AES.MODE_CBC,IV)
 plaintext = decryptor.decrypt(ciphertext)
 totalTime = time.time() - startTime
 decryptionavg += totalTime
 print('AES-CBC Decryption: Total time: %.5f seconds' %  totalTime)

def PyCrypto_AES_OFB():
 global encryptionavg
 global decryptionavg
 from Crypto.Cipher import AES
 startTime = time.time()
 encryptor = AES.new(key, AES.MODE_OFB,IV)
 ciphertext = encryptor.encrypt(plainContent)
 totalTime = time.time() - startTime
 encryptionavg += totalTime
 #print totalTime
 print('AES-CBC Encryption: Total time: %.5f seconds' %  totalTime)


 startTime = time.time()
 decryptor = AES.new(key, AES.MODE_OFB,IV)
 plaintext = decryptor.decrypt(ciphertext)
 totalTime = time.time() - startTime
 decryptionavg += totalTime
 print('AES-CBC Decryption: Total time: %.5f seconds' %  totalTime)

def PyCrypto_DES():
 global encryptionavg
 global decryptionavg
 from Crypto.Cipher import DES
 startTime = time.time()
 encryptor = DES.new(key[0:8], DES.MODE_CBC,IV[0:8])
 ciphertext = IV[0:8] + encryptor.encrypt(plainContent)
 totalTime = time.time() - startTime
 encryptionavg += totalTime
 #print totalTime
 print('DES-CBC Encryption: Total time: %.5f seconds' %  totalTime)


 startTime = time.time()
 plaintext = encryptor.decrypt(ciphertext)
 totalTime = time.time() - startTime
 decryptionavg += totalTime
 print('DES-CBC Decryption: Total time: %.5f seconds' %  totalTime)

def PyCrypto_RSA():
 global encryptionavg
 global decryptionavg
 p = plainContent
 from Crypto.PublicKey import RSA
 startTime = time.time()
 ran = Random.new().read
 key = RSA.generate(1024,ran)
 pkey = key.publickey()
 totB = (sys.getsizeof(plainContent)/sys.getsizeof(plainContent[0:80]))
 for x in range (0, totB):
  en = pkey.encrypt(plainContent[0:80], 32)
  sys.stdout.write("\rProgress: {0:.0f}%".format(x*100/42903))
  sys.stdout.flush()
 sys.stdout.write("\n")
 totalTime = time.time() - startTime
 encryptionavg += totalTime
 #print totalTime
 print('RSA Encryption: Total time: %.5f seconds' %(totalTime))

 startTime = time.time()
 for x in range (0, totB):
  de = key.decrypt(ast.literal_eval(str(en)))
  sys.stdout.write("\rProgress: {0:.0f}%".format(x*100/42903))
  sys.stdout.flush()
 sys.stdout.write("\n")
 totalTime = time.time() - startTime
 decryptionavg += totalTime
 print('RSA Decryption: Total time: %.5f  seconds' % (totalTime))


def PyCrypto_HMAC():
 global encryptionavg
 global decryptionavg
 from Crypto.Hash import HMAC
 startTime = time.time()
 h = HMAC.new(key)
 h.update(plainContent)
 totalTime = time.time() - startTime
 encryptionavg += totalTime
 #print totalTime
 print('HMAC Hash: Total time: %.5f seconds' %  totalTime)

def PyCrypto_SHA1():
 global encryptionavg
 global decryptionavg
 from Crypto.Hash import SHA
 startTime = time.time()
 h = SHA.new()
 h.update(plainContent)
 totalTime = time.time() - startTime
 encryptionavg += totalTime
 #print totalTime
 print('HMAC Hash: Total time: %.5f seconds' %  totalTime)

def PyCrypto_RC4():
 global encryptionavg
 global decryptionavg
 from Crypto.Cipher import ARC4
 from Crypto.Hash import SHA
 startTime = time.time()
 tempk = SHA.new(key + IV).digest()
 c = ARC4.new(tempk)
 cipher = IV + c.encrypt(plainContent)
 totalTime = time.time() - startTime
 encryptionavg += totalTime
 print('RC4 Encryption: Total time: %.5f seconds' %  totalTime)
 
 startTime = time.time()
 c.decrypt(cipher)
 totalTime = time.time() - startTime
 decryptionavg += totalTime
 print('RC4 Decryption: Total time: %.5f seconds' %  totalTime)

def PyCrypto_DSA():
 global encryptionavg
 global decryptionavg
 from Crypto.Random import random
 from Crypto.Hash import SHA
 from Crypto.PublicKey import DSA
 startTime = time.time()
 ke = DSA.generate(1024)
 h = SHA.new("12345678").digest()
 k = random.StrongRandom().randint(1,ke.q-1)
 sign = ke.sign(h,k)

 totalTime = time.time() - startTime
 encryptionavg += totalTime
 #print totalTime
 print('DSA sign: Total time: %.5f seconds' %  totalTime)
#===================
# PyDes Library:DES
def PyDes_DES():
 global encryptionavg

 global decryptionavg
 keyy = key[0:8]
 IVV = IV[0:8]
 p = plainContent

 from pyDes import des
 startTime = time.time()
 totalblocks = (sys.getsizeof(plainContent)/sys.getsizeof(plainContent[0:800]))

 for x in range(0,  totalblocks):
  k = des(keyy,1, IVV)
  c = k.encrypt(plainContent[0:800])
  sys.stdout.write("\rProgress: {0:.0f}%".format(x*100/5996))
  sys.stdout.flush()
 sys.stdout.write("\n")
 totalTime = time.time() - startTime
 encryptionavg += totalTime

 print('DES-CBC Encryption: Total time: %.1f minutes' %  (totalTime/60))


 startTime = time.time()
 totalblocks = (sys.getsizeof(plainContent)/sys.getsizeof(plainContent[0:800]))

 for x in range(0,  totalblocks):
  k.decrypt(c)
  sys.stdout.write("\rProgress: {0:.0f}%".format(x*100/5996))
  sys.stdout.flush()
 sys.stdout.write("\n")
 totalTime = time.time() - startTime
 decryptionavg += totalTime
 print('DES-CBC Decryption: Total time: %.1f minutes' %  (totalTime/60))


#===================
#  M2Crypto Library
def M2Crypto_AES():
 global encryptionavg
 global decryptionavg

 keyy = key
 IVV = IV
 startTime = time.time()
 keyy = base64.b64encode(keyy)
 IVV = base64.b64encode(IVV)
 encryptor = M2Crypto.EVP.Cipher('aes_256_cbc', keyy,IVV,1)
 ciphertext = encryptor.update(plainContent) + encryptor.final()
 ciphertext = base64.b64encode(ciphertext)
 totalTime = time.time() - startTime
 encryptionavg += totalTime
 print('AES-CBC Encryption: Total time: %.5f seconds' %  totalTime)

 startTime = time.time()
 cipher = M2Crypto.EVP.Cipher('aes_256_cbc', keyy, IVV, 0)
 plaintext = cipher.update(base64.b64decode(ciphertext)) + cipher.final()
 totalTime = time.time() - startTime
 decryptionavg += totalTime
 print('AES-CBC Decryption: Total time: %.5f seconds' %  totalTime)

def M2Crypto_AES_OFB():
 global encryptionavg
 global decryptionavg

 keyy = key
 IVV = IV
 startTime = time.time()
 keyy = base64.b64encode(keyy)
 IVV = base64.b64encode(IVV)
 encryptor = M2Crypto.EVP.Cipher('aes_256_ofb', keyy,IVV,1)
 ciphertext = encryptor.update(plainContent) + encryptor.final()
 ciphertext = base64.b64encode(ciphertext)
 totalTime = time.time() - startTime
 encryptionavg += totalTime
 print('AES-CBC Encryption: Total time: %.5f seconds' %  totalTime)

 startTime = time.time()
 cipher = M2Crypto.EVP.Cipher('aes_256_ofb', keyy, IVV, 0)
 plaintext = cipher.update(base64.b64decode(ciphertext)) + cipher.final()
 totalTime = time.time() - startTime
 decryptionavg += totalTime
 print('AES-CBC Decryption: Total time: %.5f seconds' %  totalTime)

def M2Crypto_RSA():
 global encryptionavg
 global decryptionavg
 startTime = time.time()
 totB = (sys.getsizeof(plainContent)/sys.getsizeof(plainContent[0:80]))
 M2Crypto.Rand.rand_seed(os.urandom(1024))
 Alice = M2Crypto.RSA.gen_key(1024, 65537,lambda x, y, z:None)
 Alice.save_key('Alice-private.pem', None)
 Alice.save_pub_key('Alice-public.pem')
 Bob = M2Crypto.RSA.gen_key(1024, 65537,lambda x, y, z:None)
 Bob.save_key('Bob-private.pem', None)
 Bob.save_pub_key('Bob-public.pem')
 WriteRSA = M2Crypto.RSA.load_pub_key('Bob-public.pem')
 for x in range(0, totB):
  CipherText = WriteRSA.public_encrypt(plainContent[0:80],M2Crypto.RSA.pkcs1_oaep_padding)
  sys.stdout.write("\rProgress: {0:.0f}%".format(x*100/42903))
  sys.stdout.flush()
 sys.stdout.write("\n")
 totalTime = time.time() - startTime
 encryptionavg += totalTime
 print('RSA Encryption: Total time: %.5f seconds' %  (totalTime))

 startTime = time.time()
 ReadRSA = M2Crypto.RSA.load_key('Bob-private.pem')
 for x in range(0, totB):
  PlainText = ReadRSA.private_decrypt(CipherText, M2Crypto.RSA.pkcs1_oaep_padding)
  sys.stdout.write("\rProgress: {0:.0f}%".format(x*100/42903))
  sys.stdout.flush()
 sys.stdout.write("\n")
 totalTime = time.time() - startTime
 decryptionavg += totalTime
 print('RSA Decryption: Total time: %.5f seconds' %  (totalTime))

def M2Crypto_HMAC():
 global encryptionavg
 global decryptionavg
 from M2Crypto.EVP import HMAC
 startTime = time.time()
 h = HMAC(key, 'sha1')
 h.update(plainContent)
 totalTime = time.time() - startTime
 encryptionavg += totalTime
 #print totalTime
 print('HMAC Hash: Total time: %.5f seconds' %  totalTime)

def M2Crypto_SHA1():
 global encryptionavg
 global decryptionavg
 from M2Crypto.EVP import MessageDigest
 startTime = time.time()
 h = MessageDigest('sha1')
 h.update(plainContent)
 totalTime = time.time() - startTime
 encryptionavg += totalTime
 #print totalTime
 print('SHA1 Hash: Total time: %.5f seconds' %  totalTime)

def M2Crypto_RC4():
 global encryptionavg
 global decryptionavg
 from M2Crypto import RC4
 startTime = time.time()
 rc4 = RC4.RC4()
 rc4.set_key(key)
 c = rc4.update(plainContent)
 totalTime = time.time() - startTime
 encryptionavg += totalTime
 #print totalTime
 print('RC4 Encryption: Total time: %.5f seconds' %  totalTime)
 startTime = time.time()
 rc4.update(c)
 totalTime = time.time() - startTime
 decryptionavg += totalTime
 #print totalTime
 print('RC4 Decryption: Total time: %.5f seconds' %  totalTime)

def M2Crypto_DSA():
 global encryptionavg
 global decryptionavg
 
 from M2Crypto import EVP, DSA, util
 startTime = time.time()
 md = EVP.MessageDigest('sha1')
 md.update(plainContent)
 digest = md.final()
 dsa = DSA.gen_params (1024,lambda x, y, z:None)
 dsa.gen_key()
 r, s = dsa.sign(digest)
 totalTime = time.time() - startTime
 encryptionavg += totalTime
 #print totalTime
 print('DSA sign: Total time: %.5f seconds' %  totalTime)
#=======================================
#=======================================
#====  Execution starts here
#read the plain file
printer_me()
inputFile = "Plain.txt"
fileObj = open(inputFile)
plainContent = fileObj.read()
fileObj.close()



# create IV , key
from Crypto import Random
IV = Random.new().read(16)
key= Random.new().read(32)


print""
print "##########################################################################"
print "==============================     Hash:     ============================="
print "=========================     HMAC    ======================="
print "=============     PyCrypto     ================"
print "-------Start HMAC hash for 10 times------------"
encryptionavg = 0
decryptionavg = 0
for x in range(0,10):
 PyCrypto_HMAC()

print "==============================================="
print "=============  Average Hash time   ============"
print('Average Hash time: %.5f seconds' %  (encryptionavg/10))


print""
print "==============     M2Crypto     ==============="
print "-------Start HMAC hash for 10 times------------"
encryptionavg = 0
decryptionavg = 0
for x in range(0,10):
 M2Crypto_HMAC()

print "==============================================="
print "=============  Average Hash time   ============"
print('Average Hash time: %.5f seconds' %  (encryptionavg/10))

print ""
print "=========================     SHA1    ======================="
print "=============     PyCrypto     ================"
print "-------Start SHA1 hash for 10 times------------"
encryptionavg = 0
decryptionavg = 0
for x in range(0,10):
 PyCrypto_SHA1()

print "==============================================="
print "=============  Average Hash time   ============"
print('Average Hash time: %.5f seconds' %  (encryptionavg/10))


print""
print "=============     M2Crypto     ================"
print "-------Start SHA1 hash for 10 times------------"
encryptionavg = 0
decryptionavg = 0
for x in range(0,10):
 M2Crypto_SHA1()
print "==============================================="
print "===  Average encryption/ decryption time   ===="
print('Average Hash time: %.5f seconds' %  (encryptionavg/10))



print""
print "##########################################################################"
print "==========================     Stream Cipher:     ========================"
print "=========================     RC4    ========================"
print "=============     PyCrypto     ================"
print "-----------Start RC4 for 10 times--------------"
encryptionavg = 0
decryptionavg = 0
for x in range(0,10):
 PyCrypto_RC4()

print "==============================================="
print "===  Average encryption/ decryption time   ===="
print('Average Encryption time: %.5f seconds' %  (encryptionavg/10))
print('Average Decryption time: %.5f seconds' %  (decryptionavg/10))

print ""
print "=============     M2Crypto     ================"
print "-----------Start RC4 for 10 times--------------"
encryptionavg = 0
decryptionavg = 0
for x in range(0,10):
 M2Crypto_RC4()
print "==============================================="
print "===  Average encryption/ decryption time   ===="
print('Average Encryption time: %.5f seconds' %  (encryptionavg/10))
print('Average Decryption time: %.5f seconds' %  (decryptionavg/10))

print ""
print "=========================   AES-OFB       ==================="
print "=============     PyCrypto     ================"
print "-------Start AES-OFB for 10 times--------------"
encryptionavg = 0
decryptionavg = 0
for x in range(0,10):
 PyCrypto_AES_OFB()
print "==============================================="
print "===  Average encryption/ decryption time   ===="
print('Average Encryption time: %.5f seconds' %  (encryptionavg/10))
print('Average Decryption time: %.5f seconds' %  (decryptionavg/10))

print ""
print "=============     M2Crypto     ================"
print "-------Start AES-OFB for 10 times--------------"
encryptionavg = 0
decryptionavg = 0
for x in range(0,10):
 M2Crypto_AES_OFB()
print "==============================================="
print "===  Average encryption/ decryption time   ===="
print('Average Encryption time: %.5f seconds' %  (encryptionavg/10))
print('Average Decryption time: %.5f seconds' %  (decryptionavg/10))





print""
print "##########################################################################"
print "========================     Asymmetric Cipher:     ======================"
print "=========================     DSA    ========================"
print "=============     PyCrypto     ================"
print "-----------Start DSA for 10 times--------------"
encryptionavg = 0
decryptionavg = 0
for i in range(0,10):
 PyCrypto_DSA()
print "==============================================="
print "===========  Average signature time   ========="
print('Average signature time: %.5f seconds' %  (encryptionavg/10))


print""
print "=============     M2Crypto     ================"
print "-----------Start DSA for 10 times--------------"
encryptionavg = 0
decryptionavg = 0
for i in range(0,10):
 M2Crypto_DSA()
print "==============================================="
print "===========  Average signature time   ========="
print('Average signature time: %.5f seconds' %  (encryptionavg/10))

print ""
print "=========================     RSA    ========================"
print "=============     PyCrypto     ================"
print "----------Start RSA for 3 times----------------"
print "RSA takes a longer time.."
encryptionavg = 0
decryptionavg = 0
PyCrypto_RSA()
PyCrypto_RSA()
PyCrypto_RSA()
print "==============================================="
print "===  Average encryption/ decryption time   ===="
print('Average Encryption time: %.5f seconds' %  (encryptionavg/3))
print('Average Decryption time: %.5f seconds' %  (decryptionavg/3))

print""
print "=============     M2Crypto     ================"
print "---------Start RSA for 3 times-----------------"
print "RSA takes a longer time.."
encryptionavg = 0
decryptionavg = 0
M2Crypto_RSA()
M2Crypto_RSA()
M2Crypto_RSA()
print "==============================================="
print "===  Average encryption/ decryption time   ===="
print('Average Encryption time: %.5f seconds' %  (encryptionavg/3))
print('Average Decryption time: %.5f seconds' %  (decryptionavg/3))




print ""
print "##########################################################################"
print "==========================     Block Cipher:     ========================="
print "=========================     AES    ========================"
print "=============     PyCrypto     ================"
print "--------Start AES256CBC  for 10 times----------"
for x in range(0,10):
 PyCrypto_AES()

print "==============================================="
print "===  Average encryption/ decryption time   ===="
print('Average Encryption time: %.5f seconds' %  (encryptionavg/10))
print('Average Decryption time: %.5f seconds' %  (decryptionavg/10))
print ""
print "=============     M2Crypto     ================"
print "--------Start AES256CBC for 10 times-----------"
encryptionavg = 0
decryptionavg = 0
for x in range(0,10):
 M2Crypto_AES()

print "==============================================="
print "===  Average encryption/ decryption time   ===="
print('Average Encryption time: %.5f seconds' %  (encryptionavg/10))
print('Average Decryption time: %.5f seconds' %  (decryptionavg/10))

print ""
print "========================     DES    ========================="
print "=============     PyCrypto     ================"
print "----------Start DES CBC for 10 times-----------"
encryptionavg = 0
decryptionavg = 0
for x in range(0,10):
 PyCrypto_DES()

print "==============================================="
print "===  Average encryption/ decryption time   ===="
print('Average Encryption time: %.5f seconds' %  (encryptionavg/10))
print('Average Decryption time: %.5f seconds' %  (decryptionavg/10))

print ""
print "=============     PyDes   ====================="
print "----------Start DES CBC for 3 times------------"
print "DES in PyDes takes super long time..."
print "Go garb a drink and come back........"
encryptionavg = 0
decryptionavg = 0
PyDes_DES()
PyDes_DES()
PyDes_DES()
print "==============================================="
print "===  Average encryption/ decryption time   ===="
print encryptionavg
print('Average Encryption time: %.1f minutes' %  (encryptionavg/60/3))
print('Average Decryption time: %.1f minutes' %  (decryptionavg/60/3))



