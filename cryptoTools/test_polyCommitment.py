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
from script import P, Pair, Fp
import cryptoTools.polyCommitment as pC
#import nizkproofs.nizkpok as nizk

poly_deg = 10
pC_SK = pC.PCommitment_Secret_Key(Fp.random().val)
g0 = P
h0 = pC_SK.alpha*g0
pC_PK = pC.PCommitment_Public_Key(Pair,poly_deg,[],[])
pC_PK.setup(g0,h0,pC_SK)

class TestPolyCommitment(unittest.TestCase):

    def setUp(self):
        self.pC_SK = pC_SK
        self.pC_PK = pC_PK
        self.poly_deg = poly_deg
        
    def produce_polynomial(self):
        phi_x_coef = []
        for i in range(poly_deg+1):
            phi_x_coef.append(Fp.random())
        
        return field.polynom(Fp,phi_x_coef)

    def test_commitment_and_verify(self):
        phi_x = self.produce_polynomial()
        phiprime_x = self.produce_polynomial()
        
        com,phiprime_x = self.pC_PK.commit(phi_x,phiprime_x)
        self.assertTrue(self.pC_PK.verifyPoly(com,phi_x,phiprime_x))


    def test_addition_of_commitments(self):
        phi1_x = self.produce_polynomial()
        phi1prime_x = self.produce_polynomial()
        com1,phi1prime_x = self.pC_PK.commit(phi1_x,phi1prime_x)
        
        phi2_x = self.produce_polynomial()
        phi2prime_x = self.produce_polynomial()
        com2,phi2prime_x = self.pC_PK.commit(phi2_x,phi2prime_x)
        
        com3 = com1+com2
        com3p,phi3p = self.ppatspk.commit(phi1_x+phi2_x,phi1prime_x+phi2prime_x)
        self.assertTrue(com3==com3p)

    def test_multiplication_of_commitment_by_a_scalar(self):
        phi1_x = self.produce_polynomial()
        phi1prime_x = self.produce_polynomial()
        com1,phi1prime_x = self.pC_PK.commit(phi1_x,phi1prime_x)
        
        a = randint(1,1000)
        com2 = a*com1
        com2p,phi2p = self.pC_PK.commit(a*phi1_x,a*phi1prime_x)
        self.assertTrue(com2==com2p)


suite = unittest.TestLoader().loadTestsFromTestCase(TestPolyCommitment)
unittest.TextTestRunner(verbosity=2).run(suite)