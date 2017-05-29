# -*- coding: utf-8 -*-
"""
Created on Mon May 29 11:16:51 2017

@author: edcuvelier
"""

from Crypto.Random.random import randint
from script import P, Q, Pair, Fr
import cryptoTools.polyCommitment as pC
import pathORAM.ringORAM as ringO
import time
import pickle

poly_deg = 10
nbOfDigits = 9
pC_SK = pC.PCommitment_Secret_Key(Fr.random().val)
g0 = P
h0 = pC_SK.alpha*g0
gp = Q
G = Fr.random().val*g0
pC_PK = pC.PCommitment_Public_Key(Pair,poly_deg,[],[])
pC_PK.setup(g0,h0,gp,pC_SK)

phone_number_PK = pC.Phone_Number_Commitment_Public_Key(pC_PK)


def produce_phoneNumbers():
    phoneNumbers = []
    rand = randint(2,poly_deg)
    for i in range(rand):
        phone_i = randint(10**nbOfDigits, 10**(nbOfDigits+1))
        phoneNumbers.append(Fr.elem(phone_i))
            
    return phoneNumbers



def test_real_example(Z = 3, S = 4, A = 4,nbChildren = 3, depth = 3,nbWords = None):
    
    # create PO Tree
    po_tree = ringO.PathORAMTree( treeID = 'test_PO_tree')
    
    RO = ringO.RingORAM(po_tree,Z = Z, S=S, A=A , nbChildren = nbChildren, depth = depth)
    
    if nbWords ==  None :
        nbWords = int(RO.tLoad/6)
        
    print 'parameters are\n Z:',Z,'\n depth:', depth,'\n number of children:', nbChildren,'\n number of blocks:', nbWords,'\n theoretic load of the tree:', RO.tLoad
    
    t1 = time.time()
    
    print 'Ring ORAM tree created'
    
    blockList  = []
    messagesList = []
    
    for i in range(nbWords):
        phoneNumbers = produce_phoneNumbers()
        # commitment on the phone number phoneNumbers[0] on other phone numbers phoneNumbers[1:]
        com , phi_x, phiprime_x = phone_number_PK.commitPhoneNode(G, phoneNumbers[0], phoneNumbers[1:])
        blockList.append(('Comit. of ☏# '+phoneNumbers[0],com))
        messagesList.append((phoneNumbers[0],phi_x, phiprime_x))
        
    print 'List of blocks generated\n Filling up the tree'
    
    t2 = time.time()
        
    RO.fillupTree(blockList)
    
    t3 = time.time()
    
    print 'Tree filled', t3-t2
    
    s = str(Z)+'_'+str(depth)+'_'+str(nbChildren)
    f = open('./posDictionaries/positionDic'+s,'w')
    pickle.dump(RO.sPD,f)
    f.close()
    
    return RO,blockList,t2-t1,t3-t2