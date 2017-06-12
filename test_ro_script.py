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
import random
import matplotlib.pyplot as plt

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



def test_real_example(Z = 4, S = 4, A = 4,nbChildren = 2, depth = 3,nbWords = None):
    
    # create PO Tree
    po_tree = ringO.PathORAMTree_for_Polynomial_Commitment(pC_PK, treeID = 'test_PO_tree')
    
    phiprime_dic = {}
    
    def cDB():
        phi_x, c = pC_PK.commit_messages([Fr.zero()])
        com, phiprime_x = c
        return com
        
    def rB(com,block_id):
        if block_id == None :
            rerand_com = cDB()
        else :
            phiprime_x = phiprime_dic[block_id]
            rerand_com, new_phiprime = pC_PK.rerandomize(com,phiprime_x)
            phiprime_dic[block_id] = new_phiprime
        return rerand_com
    
    RO = ringO.RingORAM(po_tree,Z = Z, S=S, A=A , nbChildren = nbChildren, depth = depth, createDummyBlock = cDB, rerandomizeBlock= rB)
    
    if nbWords ==  None :
        nbWords = int(RO.tLoad/4)
        
    print 'parameters are\n Z:',Z,'\n S:',S,'\n A:',A,'\n depth:', depth,'\n number of children:', nbChildren,'\n number of blocks:', nbWords,'\n theoretic load of the tree:', RO.tLoad
    
    t1 = time.time()
    
    print 'Ring ORAM tree created'
    
    blockList  = []
    messagesList = []
    
    for i in range(nbWords):
        phoneNumbers = produce_phoneNumbers()
        # commitment on the phone number phoneNumbers[0] on other phone numbers phoneNumbers[1:]
        com , phi_x, phiprime_x = phone_number_PK.commitPhoneNode(G, phoneNumbers[0], phoneNumbers[1:])
        blockID = str(phoneNumbers[0].val)     
        phiprime_dic[blockID] = phiprime_x
        blockList.append((blockID,com))
        messagesList.append((phoneNumbers[0],phi_x, phiprime_x))
        
    t2 = time.time()
    print 'List of blocks generated',t2-t1,(t2-t1)/nbWords,'\n Filling up the tree'
        
    RO.fillupTree(blockList)
    
    t3 = time.time()
    
    print 'Tree filled', t3-t2
    
    s = str(Z)+'_'+str(depth)+'_'+str(nbChildren)
    f = open('./posDictionaries/positionDic'+s,'w')
    pickle.dump(RO.sPD,f)
    f.close()
    
    return RO,blockList,t2-t1,t3-t2, phiprime_dic, messagesList
    
    
def generating_queries(RO,n):
    print RO.positionMap
    keys = RO.positionMap.keys()
    clientStashSize = []
    dummyStashSize = []
    t_mean = 0
    for i in range(n):
        blockID = random.sample(keys,1)[0]
        print '\n ###\t query nb',i, 'on block', blockID
        t1 = time.time()
        RO.queryBlock(blockID)
        t2 = time.time()
        t_mean += t2-t1
        clientStashSize.append(len(RO.clientStash))
        dummyStashSize.append(len(RO.dummyStash))
        RO.checkSync()
        #print RO.positionMap
        
    plt.plot(range(n), clientStashSize)
    plt.plot(range(n), dummyStashSize)
    plt.show()
    
    print t_mean/n, 'sec per query'
    print RO.dummyCounter, 'dummy blocks created'
        
    return clientStashSize,dummyStashSize