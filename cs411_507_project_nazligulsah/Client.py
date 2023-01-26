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
# y*2 = x*3 +0*x + 7 mod p elliptic curve eq

#convert student id to bytes
stuID = 26392
m = stuID.to_bytes((stuID.bit_length()+7)//8, byteorder='big')

# create curve
curve = Curve.get_curve('secp256k1')
P = curve.generator
n = curve.order
# create keygen from algorithm in the pdf
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
    #m_bytes = m.to_bytes((m.bit_length()+7)//8, byteorder='big')
    temp = r_bytes + m
    h_obj = SHA3_256.new(temp)
    h = h_obj.hexdigest()
    h=int(h, 16)
    h = h % n
    s = (k-Sa*h) % n
    return h,s
def SigVer(h,s,m,Qa):
    V = s*P + h*Qa
    v = (V.x) % n
    # h′ = SHA3 256(v||m) (mod n)
    v_bytes = v.to_bytes((v.bit_length()+7)//8, byteorder='big')
    #m = m.to_bytes((m.bit_length()+7)//8, byteorder='big')
    temp = v_bytes+m
    hx_obj = SHA3_256.new(temp)
    hx = hx_obj.hexdigest()
    hx =int(hx, 16)
    hx = hx % n
    #Accept the signature only if h = h′
    if hx == h:
        answer = "accept the signature"
    #Reject it otherwise.
    else:
        answer = "reject the signature"
    return answer
# Identity Key
#rcode = input("Enter your rcode: ")
#rcode = int(rcode)
#ResetIK(rcode)
#Sa, Qa = KeyGen(n) 
#h, s = SigGen(m,Sa,n)
#x = Qa.x
#y = Qa.y
#IKRegReq(h,s,x,y)
#code = input("Enter your code: ")
#code = int(code)
#IKRegVerify(code) 
#print("Here is my private Identity Key")
#print(Sa) #71749651445945796616297888392630939370084595458380499484727354773767135348279
#SPK 
Sa = 71749651445945796616297888392630939370084595458380499484727354773767135348279
SPKs_pri , SPKs_pub = KeyGen(n)
print("My private SPK is:", SPKs_pri)
#My private SPK is: 89588183203201619325042491740113777812668520239074971403491314680977203997976
spk_x = SPKs_pub.x
spk_y = SPKs_pub.y
#convert bytes to SPKs_pri and SPKs_pub to create pre_key
spk_x = spk_x.to_bytes((spk_x.bit_length()+7)//8, byteorder='big')
spk_y = spk_y.to_bytes((spk_y.bit_length()+7)//8, byteorder='big')
pre_key =  spk_x + spk_y
x = SPKs_pub.x
y = SPKs_pub.y
#Sa Identity private key I genereted
SPK_h, SPK_s= SigGen(pre_key,Sa,n)
SPKs_pub_x, SPKs_pub_y, server_h ,server_s,  = SPKReg(SPK_h,SPK_s,x, y) 
print("Server's Public SPK is (x and y):")
print(SPKs_pub_x)
print(SPKs_pub_y)
#Server's Public SPK is (x and y):
#85040781858568445399879179922879835942032506645887434621361669108644661638219
#46354559534391251764410704735456214670494836161052287022185178295305851364841
#convet bytes to SPKs_pub_x an SPKs_pub_y to get m for SigVer
SPKs_pub_x2= SPKs_pub_x.to_bytes((SPKs_pub_x.bit_length()+7)//8, byteorder='big')
SPKs_pub_y2= SPKs_pub_y.to_bytes((SPKs_pub_y.bit_length()+7)//8, byteorder='big')
m = SPKs_pub_x2 + SPKs_pub_y2
# check SigVer. It is succcesfull
answer = SigVer(server_h,server_s, m, IKey_Ser)
print(answer)
#accept the signature

#OTK 
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

#{0: [93536905020291431459174971137226296653620948416811094966752650930650495786766, 8767264597644411180416387712068696039646158409735708170172708906115435947439, 98353153840726762405583428960112173754022227940763540521883621173955259003612], 
# 1: [109603659421659577164685801512040825439328080674353234860290242409677120419440, 76528310414970282984135410389818366713695529181194199431152598740360009367593, 32514558320817581837064466085366727857024265005884251738708519431384642938996], 
# 2: [84640811628794276127706310716062961593159804279307845579885288891482339674701, 7721213133872106474427885195958625095209207971501991477200424429988674358940, 108735578038319128631487938189181868144555294635049564281337564725111433295258], 
# 3: [45727697196261594439613243600842886021459944904774988381903229543801693124218, 111882333471299407480628055721959423281793141545276845548027370040786712212402, 24718383074729041726760588054723858650360593446303763656957801054391968204967], 
# 4: [47782386226010091559829731712355749500452296673942028727088394545541644637822, 32539337321147112482280581186815908399396878144913723619362498711260594009782, 109181442634446802874332986067945989561671703034375127206681975216777637884029], 
# 5: [96963756388091099276141023934172962790638200958842294130293731428943665509067, 44310367977594233024860251243484112365205331964050987845805676320010427281205, 109141394735032483537186552711566844074037610544860364958734678314401156037738], 
# 6: [106367445849071230025374029283618326620109818541253528229029317502673373435609, 56477099608472386223958846775621724175170136915859089842181439730629134154623, 3286152325994458948657694988352233499433695323347153422233931096864461210102], 
# 7: [65259469569106273150399756833209410529947635016787067059681535007875685262587, 40277977114823619940516920777469339669017948035044363863269508228974887063862, 86034572061285136821829670216911178896326764939176341224232213577450194617379], 
# 8: [67192360722809841731745244455388302226287563433936807113112790987376248802623, 88584639894438879368711892090119863159078258575148462643755894507670046253643, 18184123341698608099282275085064614116990973339696666418895233159085854522400], 
# 9: [30536069078111723414219314151061798917794978061739687160177382403456152499623, 56120330045131084036061290762304131185367455722081155559176010419533666955419, 93244106206129420366302562998365848682900960331324391916746680635042650900863], 
#}

#ResetOTK(h,s)
#ResetSPK(h,s)
#rcode = input("Enter your rcode: ")
#rcode = int(rcode)
#ResetIK(rcode)



