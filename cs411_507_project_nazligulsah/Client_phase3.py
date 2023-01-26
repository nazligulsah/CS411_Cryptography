# -*- coding: utf-8 -*-
from client_basics_Phase3 import IKey_Ser, ResetOTK,ResetIK,ReqMsg,Status, PseudoSendMsgPH3,reqOTKB, SendMsg,OTKReg
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

API_URL = 'http://10.92.52.175:5000/'
stuID = 26392

stuIDB = 18007
#m = stuID.to_bytes((stuID.bit_length()+7)//8, byteorder='big')

curve = Curve.get_curve('secp256k1')
P = curve.generator
n = curve.order


def encrypt(KENC,signature_ciphertext,decmsg):
  cipher_enc = AES.new(KENC, AES.MODE_CTR)
  ctext_enc = cipher_enc.nonce + cipher_enc.encrypt(decmsg.encode()) + signature_ciphertext.digest()
  return ctext_enc
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

# old variables
sA = 71749651445945796616297888392630939370084595458380499484727354773767135348279

h = 41144585473126337816775518319592030012523194136867294363453812159400738807338
s = 52674414007574588265553552137450742626393294177872942206288694588614887717686
#ResetOTK(h,s)
#All OTKs deleted !
#Status(stuID, h, s)
#'You have 0 unread messages in your mailbox.\n You have 0 OTKs left. The largest key id is None'
#we run Client.py
#{0: [31491290576922032439471755893312376018607889552683297985534500834444551703582, 114155041332675469793873801351362228237579949604721322013872340060305848605713, 70033025821371037624253800785217388462188093973619090195857197632113045857072], 
# 1: [61669199993580399420771442059228683782619695930826527250379470683108027916543, 84324641241349005266376604157205401771371619676191300686521268374922216365303, 98573990724026140046060806393392498105858924936479454420398459400199192092386], 
# 2: [94923688195751541006921557091713604733254875281420278910166662746668164562600, 71755635177641390064513427683462834744006909338498363309037022785950359371893, 102074948786481133179575798141866792592328677415898264091177542780589108081784], 
# 3: [76242628233288250096287935358437863453176540323953419608143137155313251412693, 95367831809067967001836651083994311527935804080392911280744631843763253598794, 39588987236193896908290265351148074437341359673987851795649789204733433263974], 
# 4: [110730309166011817291510569274057283879796318521892161394910094150875360172672, 10543037622240588315782318293768528951932744684707172360248596148661172761038, 50853611805652690500602443879938745119964839886248044857468896069123639529714], 
# 5: [13787469497287315840388409264128996103340197403264983932573675042508882555198, 48891536624602351192615452038203197345453005205716434611004287527763409070820, 115177725524432012234555755370948414090551464708679656147982126573664517588947], 
# 6: [88214579334917058036907515894909770352081926707517143639415562180601106285361, 71249421133998240576770422068278489295068021497144983725514344571777126018952, 61925385769194499903535678614803917267438614862544912801405442289333783162996], 
# 7: [11997606778084944123030216472353718146647348542285641257076450582877667599470, 58799574527499713707590490542458126812004447284913202046895980036325642181814, 81541948064682339480189016481001417353806523836723006659329089597888859560414], 
# 8: [114638580145196610954549014041897765540536964390704338792002326330382386135124, 50720977741679773379334437707577749372820420888375955445419320791054611243069, 82702022925101720565022790233508577345765603516461167771326798762061838522336], 
# 9: [68811346895040124324317966873877344075141785912306534943274226488894071748500, 44068964908404204540837386266744565843414352590583499081578123335264281011041, 55002277066088110571796994086447277066342354744112738392821634034851260949096]}
PseudoSendMsgPH3(h,s)
#Your favourite pseudo-client sent you 5 messages. You can get them from the server
#Status(stuID, h, s)
#{'numMSG': 5, 'numOTK': 10, 'StatusMSG': 'You have 5 unread messages in your mailbox.\n You have 10 OTKs left. The largest key id is 10'}


#h2,s2 = SigGen(stuIDB,sA,n)
#print(h2)
h2 = 49780725706595481209223951163215929580592191207092678432476216277839379333602
s2 = 96023763575270953062602991917563958593077068858133093850202047267230240722158
#reqOTKB(stuID, stuIDB, h2, s2)
#{'KEYID': 724, 'OTK.X': 11934013700275823306961172510517269653203013854124831490400149139150988909170, 'OTK.Y': 100045954204810886701754513615618374342185387134742731594249675485594406572208}


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
  #encrypt(KENC,signature_ciphertext,decmsg)
  val = decmsg
  cipher_enc = AES.new(KENC, AES.MODE_CTR)
  ctext_enc = cipher_enc.nonce + cipher_enc.encrypt(val.encode()) + signature_ciphertext.digest()
  
  #print("Decrypted message is", decmsg)
  stuIDB = messagelist[j]['IDB']

  try:
    #h.hexverify(mac)
    signature_ciphertext.verify(mac)
    print("Hmac verified")
    #Checker(stuID, stuIDB, MSG_ID, decmsg)
    meslist.append(decmsg)
  except ValueError:
    print("Hmac couldn't be verified")
    #Checker(stuID, stuIDB, MSG_ID, "INVALIDHMAC")
  otkid = 724 
  ctext_enc = int.from_bytes(ctext_enc, byteorder = 'big')
  SendMsg(stuID, stuIDB, otkid, MSG_ID, ctext_enc, EK_X, EK_Y)
           
print(meslist)
# ['https://www.youtube.com/watch?v=1hLIXrlpRe8', 'https://www.youtube.com/watch?v=KsEjdfXudfM', 'https://www.youtube.com/watch?v=2aHkqB2-46k', 'https://www.youtube.com/watch?v=379oevm2fho', 'https://www.youtube.com/watch?v=KsEjdfXudfM'] 

Status(stuID, h, s)
ReqMsg(h,s)

answer = input("Do you want to create OTKs?(yes:1, no:0)")

if answer == "1":
    SPKs_pub_x = 85040781858568445399879179922879835942032506645887434621361669108644661638219
    SPKs_pub_y = 46354559534391251764410704735456214670494836161052287022185178295305851364841
    SPKs_pub_x2= SPKs_pub_x.to_bytes((SPKs_pub_x.bit_length()+7)//8, byteorder='big')
    SPKs_pub_y2= SPKs_pub_y.to_bytes((SPKs_pub_y.bit_length()+7)//8, byteorder='big')
    m = SPKs_pub_x2 + SPKs_pub_y2
    # check SigVer. It is succcesfull

    #accept the signature

    #OTK 
    SPKs_pri = 89588183203201619325042491740113777812668520239074971403491314680977203997976
    SPK_pub = Point(SPKs_pub_x,SPKs_pub_y,curve)
    T = SPKs_pri*SPK_pub
    #create U
    T_x = T.x
    T_y = T.y
    T_x2 = T_x.to_bytes((T_x.bit_length()+7)//8, byteorder='big')
    T_y2= T_y.to_bytes((T_y.bit_length()+7)//8, byteorder='big')
    U = T_x2 + T_y2 + b'NoNeedToRideAndHide'
    K = SHA3_256.new(U) #getting the hash
    k = K.digest()
    messagelist = []
    keyIDlist = []
    for i in range(11):
        mlist = []
        keyID = i
        private_OTK , public_OTK = KeyGen(n)
        #print(keyID," th is generated. Private part:", private_OTK ,
            #"Public (x coordinate)=", public_OTK.x,
            #"Public (y coordinate)=", public_OTK.y)
        
        public_OTK_x = public_OTK.x
        public_OTK_y = public_OTK.y
        public_OTK_x2= public_OTK_x.to_bytes((public_OTK_x.bit_length()+7)//8, byteorder='big')
        public_OTK_y2= public_OTK_y.to_bytes((public_OTK_y.bit_length()+7)//8, byteorder='big')
        mes = public_OTK_x2 + public_OTK_y2
        #print("mes:",mes)
        hmac = HMAC.new(k, mes, digestmod=SHA256)
        hmac = hmac.hexdigest()
        #print("hmac:", hmac)
        if keyID != 11:
            OTKReg(keyID,public_OTK.x,public_OTK.y,hmac)
            #print("OTK with ID number",keyID," is registered successfully")
            mlist.append(private_OTK)
            mlist.append(public_OTK.x)
            mlist.append(public_OTK.y)
            messagelist.append(mlist)
            keyIDlist.append(keyID)
        else :
            print("Key memory is full. There are 10 keys registered. No need to register more keys")
    
    res = {}
    for key in keyIDlist:
        for value in messagelist:
            res[key] = value
            messagelist.remove(value)
            break  
    res.popitem() # not 11 items 10 items 
    print(str(res))
else:
    print("thank you! See you again!")
