# -*- coding: utf-8 -*-
"""
Created on 2017

Author : Edouard Cuvelier
Affiliation : Université catholique de Louvain - ICTEAM - UCL Crypto Group
Address : Place du Levant 3, 1348 Louvain-la-Neuve, BELGIUM
email : firstname.lastname@uclouvain.be
"""

import unittest
import mathTools.field as field
from Crypto.Random.random import randint
from script import P, Q, Pair, Fr
import cryptoTools.polyCommitment as pC
from random import sample
#import nizkproofs.nizkpok as nizk

poly_deg = 10
nbOfDigits = 13
pC_SK = pC.PCommitment_Secret_Key(Fr.random().val)
g0 = P
h0 = pC_SK.alpha*g0
gp = Q
G = Fr.random().val*g0
pC_PK = pC.PCommitment_Public_Key(Pair,poly_deg,[],[])
pC_PK.setup(g0,h0,gp,pC_SK)

phone_number_PK = pC.Phone_Number_Commitment_Public_Key(pC_PK)

class TestPolyCommitment(unittest.TestCase):

    def setUp(self):
        self.pC_SK = pC_SK
        self.pC_PK = pC_PK
        self.poly_deg = poly_deg
        self.phone_number_PK = phone_number_PK
        
    def produce_polynomial(self):
        phi_x_coef = []
        for i in range(poly_deg+1):
            phi_x_coef.append(Fr.random())
        
        return field.polynom(Fr,phi_x_coef)
        
    def produce_messages(self):
        mList = []
        rand = randint(1,poly_deg)
        for i in range(rand):
            mList.append(Fr.random())
            
        return mList
        
    def produce_phoneNumbers(self,numberOfDigits):
        phoneNumbers = []
        rand = randint(2,poly_deg)
        for i in range(rand):
            phone_i = randint(10**numberOfDigits, 10**(numberOfDigits+1))
            phoneNumbers.append(Fr.elem(phone_i))
            
        return phoneNumbers

    def test_commitment_and_verify(self):
        phi_x = self.produce_polynomial()
        phiprime_x = self.produce_polynomial()
        
        com,phiprime_x = self.pC_PK.commit(phi_x,phiprime_x)
        self.assertTrue(self.pC_PK.verifyPoly(com,phi_x,phiprime_x))
        
    def test_commitment_and_verify_without_chosing_randomness(self):
        #phi_x = self.produce_polynomial()
        phi_x = self.pC_PK.randomPolynomial()
        
        com,phiprime_x = self.pC_PK.commit(phi_x)
        self.assertTrue(self.pC_PK.verifyPoly(com,phi_x,phiprime_x))
        
    def test_commitment_on_messages_list_and_verify(self):
        mList = self.produce_messages()
        phiprime_x = self.produce_polynomial()
        
        phi_x, C = self.pC_PK.commit_messages(mList,phiprime_x)
        com, phiprime_x = C
        self.assertTrue(self.pC_PK.verifyPoly(com,phi_x,phiprime_x))

    def test_addition_of_commitments(self):
        phi1_x = self.produce_polynomial()
        com1,phi1prime_x = self.pC_PK.commit(phi1_x)
        
        phi2_x = self.produce_polynomial()
        com2,phi2prime_x = self.pC_PK.commit(phi2_x)
        
        com3 = com1+com2
        com3p,phi3p = self.pC_PK.commit(phi1_x+phi2_x,phi1prime_x+phi2prime_x)
        self.assertTrue(com3==com3p)
        
    def test_rerandomization_of_commitment(self):
        phi1_x = self.produce_polynomial()
        com1,phi1prime_x = self.pC_PK.commit(phi1_x)
        phi1second_x = self.produce_polynomial()
        
        com2_x, phi2prime_x = self.pC_PK.rerandomize(com1,phi1prime_x,phi1second_x)
        
        self.assertTrue(self.pC_PK.verifyPoly(com2_x,phi1_x,phi2prime_x)) 
        

    def test_multiplication_of_commitment_by_a_scalar(self):
        phi1_x = self.produce_polynomial()
        com1,phi1prime_x = self.pC_PK.commit(phi1_x)
        
        a = randint(1,1000)
        com2 = a*com1
        com2p,phi2p = self.pC_PK.commit(a*phi1_x,a*phi1prime_x)
        self.assertTrue(com2==com2p)
        
    def test_verification_of_evaluation_of_polynomial_using_a_witness(self):
        phi_x = self.produce_polynomial()
        com,phiprime_x = self.pC_PK.commit(phi_x)
        
        khi_x = self.produce_polynomial()
        com2, khiprime_x = self.pC_PK.commit(khi_x)
        
        b = Fr.random()
        b,phi_b,phiprime_b,w_b = self.pC_PK.createWitness(phi_x,phiprime_x,b)
        
        self.assertTrue(self.pC_PK.verifyEval(com,b,phi_b,phiprime_b,w_b))
        
        b,khi_b,khiprime_b,wk_b = self.pC_PK.createWitness(khi_x,khiprime_x,b)
        self.assertFalse(self.pC_PK.verifyEval(com,b,khi_b,khiprime_b,wk_b))
        
        
    def test_verification_of_batch_evaluation_of_polynomial_using_a_witness(self):
        
        phi_x = self.produce_polynomial()
        com,phiprime_x = self.pC_PK.commit(phi_x)
        
        B = []
        for i in range(int((self.pC_PK.deg_pol+1)/2)):
            B.append(Fr.random())
            
        B, rem1_x, rem2_x, w_B = self.pC_PK.createWitnessBatch(phi_x,phiprime_x,B)
        
        self.assertTrue(self.pC_PK.verifyEvalBatch(com, B, rem1_x, rem2_x, w_B))
        
        
    def test_openingNIZKPOK(self):
        phi_x = self.produce_polynomial()
        com,phiprime_x = self.pC_PK.commit(phi_x)
        
        khi_x = self.produce_polynomial()
        com2, khiprime_x = self.pC_PK.commit(khi_x)
        
        proof = self.pC_PK.openingNIZKPOK(com,phi_x,phiprime_x)
        proof2 = self.pC_PK.openingNIZKPOK(com2,khi_x,khiprime_x)
        
        self.assertTrue(self.pC_PK.checkOpeningNIZKPOK(com,proof))
        self.assertFalse(self.pC_PK.checkOpeningNIZKPOK(com,proof2))
        
    def test_ZKSProof(self):
        
        mList = self.produce_messages()
        phi_x,D = self.pC_PK.commit_messages(mList)
        com, phiprime_x = D
        
        m_in_list = sample(mList,1)[0]
        m_not_in_list = Fr.random()
        while m_not_in_list in mList :
            m_not_in_list = Fr.random()
            
        proof1 = self.pC_PK.queryZKS(com, phi_x, phiprime_x, m_in_list, True)
        proof2 = self.pC_PK.queryZKS(com, phi_x, phiprime_x, m_not_in_list, False)
        
        self.assertTrue(self.pC_PK.verifyZKS(com,m_in_list,proof1))
        self.assertTrue(self.pC_PK.verifyZKS(com,m_not_in_list,proof2))
        
    ############################################################################
    # PHONE NUMBER COMMITMENT
        
    def test_commit_phone_number_and_verify(self):
        phoneList = self.produce_phoneNumbers(nbOfDigits)
        #print phoneList
        com , phi_x, phiprime_x = self.phone_number_PK.commitPhoneNode(G, phoneList[0], phoneList[1:])
        self.assertTrue(self.phone_number_PK.verifyPolyPhoneNumber(G, phoneList[0],com,phi_x,phiprime_x))
        
    def test_verification_of_evaluation_of_polynomial_using_a_witness_for_phone_number(self):
        
        phoneList = self.produce_phoneNumbers(nbOfDigits)
        com , phi_x, phiprime_x = self.phone_number_PK.commitPhoneNode(G, phoneList[0], phoneList[1:])
        
        b = sample( phoneList[1:],1)[0]
        b,phi_b,phiprime_b,w_b = self.pC_PK.createWitness(phi_x,phiprime_x,b)
        
        self.assertTrue(self.phone_number_PK.verifyEvalPhoneNumber(G, phoneList[0], com, b, phi_b, phiprime_b, w_b))
        
    def test_verification_of_batch_evaluation_of_polynomial_using_a_witness_for_phone_number(self):
         
        phoneList = self.produce_phoneNumbers(nbOfDigits)
        com , phi_x, phiprime_x = self.phone_number_PK.commitPhoneNode(G, phoneList[0], phoneList[1:])
        
        rand = randint(1,len(phoneList[1:]))
        B = sample( phoneList[1:],rand)
        #print B
        B, rem1_x, rem2_x, w_B = self.pC_PK.createWitnessBatch( phi_x, phiprime_x, B)
        
        self.assertTrue(self.phone_number_PK.verifyEvalBatchPhoneNumber( G, phoneList[0], com, B, rem1_x, rem2_x, w_B))

            
        

suite = unittest.TestLoader().loadTestsFromTestCase(TestPolyCommitment)
unittest.TextTestRunner(verbosity=2).run(suite)