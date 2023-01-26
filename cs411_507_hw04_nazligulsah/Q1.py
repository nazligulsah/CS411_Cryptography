import random
import requests
from random import randint

API_URL = 'http://cryptlygos.pythonanywhere.com'

my_id = 26392  #Change this to your ID


def RSA_Oracle_Get():
  response = requests.get('{}/{}/{}'.format(API_URL, "RSA_Oracle", my_id)) 	
  c, N, e = 0,0,0 
  if response.ok:	
    res = response.json()
    print(res)
    return res['c'], res['N'], res['e']
  else:
    print(response.json())

def RSA_Oracle_Query(c_):
  response = requests.get('{}/{}/{}/{}'.format(API_URL, "RSA_Oracle_Query", my_id, c_)) 
  print(response.json())
  m_= ""
  if response.ok:	m_ = (response.json()['m_'])
  else: print(response)
  return m_

def RSA_Oracle_Checker(m):
  response = requests.put('{}/{}/{}/{}'.format(API_URL, "RSA_Oracle_Checker", my_id, m))
  print(response.json())

def egcd(a, b):
    x,y, u,v = 0,1, 1,0
    while a != 0:
        q, r = b//a, b%a
        m, n = x-u*q, y-v*q
        b,a, x,y, u,v = a,r, u,v, m,n
    gcd = b
    return gcd, x, y

def modinv(a, m):
    a = a % m
    if (a < -m):
        a = a+m
    gcd, x, y = egcd(a, m)
    if gcd != 1:
        return None  # modular inverse does not exist
    else:
        return x % m
#get the parameters
c, N, e = RSA_Oracle_Get()
r = 30 #this is a random number, 
sended = pow(r, e, N)*c
c_ = sended % N

#choose a ciphertext and get the corresponding plaintext
m_ = RSA_Oracle_Query(c_)   
#m_ = r*m mod N
inv_r = modinv(r, N)  
message = m_ * inv_r
message = message % N
print("message: ",message)

byte_array = message.to_bytes(message.bit_length() // 8 + 1, byteorder= "big")
messagetext = byte_array.decode("utf-8")

res = byte_array
print(res)

print("messagetext: ", messagetext)
m = byte_array
#Calculte m using m_

RSA_Oracle_Checker(messagetext) #m should be string

"""{'c': 110377584392839259815537195507717514565103709482154125755198201438254029506277364623092568438143756758157539722175634187445455116893099467190857617973647383888472888127034060878098015747550895577143754237392429714148148727388170506645673232775228375244234027045238139012767655096976752588310367299449902477670963131266193919042654721337672755060065995302247595630549374009962346102289783904858484908653320769695636190151741088197823192139303820109960196731498434671581354064646594019883904839660408186813621614523885643426778374386373240898528465437027705035809059872357104075204677651536356352401400187334639011357, 'N': 26730193570266765146162350221168420509871934899990091789117873504768221934606685360435438936908077210466679136999579932797253012779833752983832169594271580544378771750110731296030469292041055213628244637975822798385488045908955631596867144311774417315862504805102114856953739328867788553915427321726547313164893402975853174087536540188026367454810684743884694561863225039733661354862832518078317839212097962152694395445052188033757708623632647020463909902694284026357971563894022486706630875757636780097293601571122207982209648818861118125339556374786424545966614343849812967029986858958970306250009289226144844365253, 'e': 65537}
{'m_': 18287477167346339561913746475360599955421600698845450651759703375514552203814128795969387063288218065129092150}
message:  609582572244877985397124882512019998514053356628181688391990112517151740127137626532312902109607268837636405
b'Bravo! You find it. Your secret code is 65695'
messagetext:  Bravo! You find it. Your secret code is 65695
Congrats"""
