# -*- coding: utf-8 -*-
from client_basics_Phase2 import IKRegReq,IKRegVerify, IKey_Ser, SPKReg,ResetSPK,OTKReg,ResetOTK,ResetIK,PseudoSendMsg,ReqMsg,Checker
import random
import string
import math
import sympy
from Crypto.Hash import SHA3_256, HMAC, SHA256, HMAC
from random import randint, seed
from Crypto import Random
from ecpy.curves import Curve, Point
import requests
from Crypto.Cipher import AES

from client_basics_Phase3 import PseudoSendMsgPH3
API_URL = 'http://10.92.52.175:5000/'
stuID = 26392
m = stuID.to_bytes((stuID.bit_length()+7)//8, byteorder='big')

curve = Curve.get_curve('secp256k1')
P = curve.generator
n = curve.order

sA = 71749651445945796616297888392630939370084595458380499484727354773767135348279
def KeyGen(n):
    #picks a random secret key 0 < sA < q − 1 
    Sa =random.randrange(0,n-1)
    Qa = Sa*P
    return Sa,Qa
#create SigGen
def SigGen(m,Sa,n):
    k=random.randrange(0,n-2)
    R = k*P
    r = (R.x) % n
    # convert bytes r and m
    r_bytes = r.to_bytes((r.bit_length()+7)//8, byteorder='big')
    # h = SHA3 256(r||m) (mod n)
    m_bytes = m.to_bytes((m.bit_length()+7)//8, byteorder='big')
    temp = r_bytes + m_bytes
    h_obj = SHA3_256.new(temp)
    h = h_obj.hexdigest()
    h=int(h, 16)
    h = h % n
    s = (k-Sa*h) % n
    return h,s

#h,s = SigGen(stuID,sA,n)
#print("h:",h)
h = 41144585473126337816775518319592030012523194136867294363453812159400738807338
s = 52674414007574588265553552137450742626393294177872942206288694588614887717686
#print("s:",s)
PseudoSendMsg(h,s)
#Sending message is:  {'ID': 26392, 'H': 41144585473126337816775518319592030012523194136867294363453812159400738807338, 'S': 52674414007574588265553552137450742626393294177872942206288694588614887717686}
#Your favourite pseudo-client sent you 5 messages. You can get them from the server

messagelist = []
for i in range(0,5):
    temp = []
    h, s = SigGen(stuID, sA,n)
    mes = {'ID': stuID, 'S': s, 'H': h }
    #ReqMsg(h,s)
    response = requests.get('{}/{}'.format(API_URL, "ReqMsg"), json = mes)
    #print(response.json())
    messagelist.append(response.json())
    print(response.json()) 
   

#print("message list:",messagelist)

meslist=[]
for j in range(0,5):
 
  i = int(messagelist[j]['OTKID']) #getting corresponding values from the dictionary
  EK_X = messagelist[j]['EK.X']
  EK_Y = messagelist[j]['EK.Y']
  EK = Point(EK_X,EK_Y,curve) #constructing the pointing
  #print("EK:", EK)
  MSG_ID = messagelist[j]['MSGID']
  
  #OTK_9
  
  private_OTK = 68811346895040124324317966873877344075141785912306534943274226488894071748500
  #private_OTK = 30536069078111723414219314151061798917794978061739687160177382403456152499623 
  T_ks = private_OTK*EK
  T_ks_x = T_ks.x
  T_ks_y = T_ks.y
  T_ks_x2 = T_ks_x.to_bytes((T_ks_x.bit_length()+7)//8, byteorder='big')
  T_ks_y2= T_ks_y.to_bytes((T_ks_y.bit_length()+7)//8, byteorder='big')
  U_ks = T_ks_x2 + T_ks_y2 + b'MadMadWorld'
  K_ks = SHA3_256.new(U_ks) #getting the hash
  k_ks = K_ks.digest()
  
  #print(k_ks)
  #KENC = SHA3 256(KKDF ∥ b’LeaveMeAlone’)
  TEMP = k_ks + b'LeaveMeAlone'
  KENC = SHA3_256.new(TEMP)
  KENC = KENC.digest()
  #KHMAC = SHA3 256(KENC ∥ b’GlovesAndSteeringWheel’)
  TEMP2 = KENC + b'GlovesAndSteeringWheel'
  KHMAC = SHA3_256.new(TEMP2)
  KHMAC = KHMAC.digest()
  #print(i,MSG_ID)
  #print("KMAC:",KHMAC)
  if MSG_ID == 1:  
      hmac = KHMAC
      #print(hmac)
  if MSG_ID > 1:
      for i in range (1,MSG_ID):
            #KKDF.Next = SHA3 256(KHMAC ∥ b’YouWillNotHaveTheDrink’)
            TEMP = KHMAC + b'YouWillNotHaveTheDrink'
            KKDFNext = SHA3_256.new(TEMP)
            KKDFNext = KKDFNext.digest()
            #KENC = SHA3 256(KKDF ∥ b’LeaveMeAlone’)
            TEMP1 = KKDFNext+ b'LeaveMeAlone'
            KENC = SHA3_256.new(TEMP1)
            KENC = KENC.digest()
            #KHMAC = SHA3 256(KENC ∥ b’GlovesAndSteeringWheel’)
            TEMP2 = KENC + b'GlovesAndSteeringWheel'
            KHMAC = SHA3_256.new(TEMP2)
            KHMAC = KHMAC.digest()
      hmac = KHMAC
      #print(khmac)
  ctext=messagelist[j]['MSG']
  #message then mac adrsi al msg = nonce∥ciphertext∥MAC
  ctext2= ctext.to_bytes((ctext.bit_length()+7)//8, byteorder='big')
 

  msg = ctext2[8:len(ctext2)- 32] #slicing the message
  #print("msg is", msg)
  mac = ctext2[len(ctext2)- 32:]
  #print("mac is", mac)
  signature_ciphertext = HMAC.new(hmac, digestmod=SHA256)
  signature_ciphertext.update(msg)
  ctext2 = ctext2[:len(ctext2)- 32]
  #print("ctext is", ctext)
  cipher = AES.new(KENC, AES.MODE_CTR,nonce=ctext2[:8]) #AES decryption
  decmsg = cipher.decrypt(ctext2[8:])
  decmsg = decmsg.decode() 
  
  #print("Decrypted message is", decmsg)
  stuIDB = messagelist[j]['IDB']

  try:
    #h.hexverify(mac)
    signature_ciphertext.verify(mac)
    print("Hmac verified")
    Checker(stuID, stuIDB, MSG_ID, decmsg)
    meslist.append(decmsg)
  except ValueError:
    print("Hmac couldn't be verified")
    Checker(stuID, stuIDB, MSG_ID, "INVALIDHMAC")
           
print(meslist)


#print(KS_list)  

