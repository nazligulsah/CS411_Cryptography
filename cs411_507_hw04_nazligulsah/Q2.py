import math
import timeit
import random
import requests
import sympy
import warnings
from RSA_OAEP import RSA_OAEP_Enc
from Crypto.Hash import SHA3_256
from Crypto.Hash import SHA3_384
from Crypto.Hash import SHA3_512
from Crypto.Hash import SHAKE128, SHAKE256

API_URL = 'http://cryptlygos.pythonanywhere.com'

my_id = 26392  ## Change this to your ID number

def RSA_OAEP_Get():
  response = requests.get('{}/{}/{}'.format(API_URL, "RSA_OAEP", my_id )) 	
  c, N, e = 0,0,0 
  if response.ok:	
    res = response.json()
    print(res)
    return res['c'], res['N'], res['e']
  else:
    print(response.json())
    return c, N, e

def RSA_OAEP_Checker(PIN_):
  # Client sends PIN_
  response = requests.put('{}/{}/{}/{}'.format(API_URL, "RSA_OAEP", my_id, PIN_))
  print(response.json())

#get the parameters
k0 = 8
c, N, e = RSA_OAEP_Get()
for m in range(0,10000): #4 digit 
    for R in range(2**(k0-1), 2**k0-1): # 8 unsigned integer
		   # c = 
        if(RSA_OAEP_Enc(m, e, N, R)== 11352871632598964629356838860088839410463425369482314036274872077619009180504):
		        print("M = ",m , " R = ",R)
            #print("R = ",R)
	

#Calculate the PIN_ and check your answer
PIN_ = 8211
RSA_OAEP_Checker(PIN_)

"""{'c': 11352871632598964629356838860088839410463425369482314036274872077619009180504, 'N': 75912732707060243642078909648401302780483043992228012220203806825283170905549, 'e': 65537}
M =  8211
R =  130
Congrats"""