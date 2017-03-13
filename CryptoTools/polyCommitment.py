# -*- coding: utf-8 -*-
"""
Created on 2017

Author : Edouard Cuvelier
Affiliation : Université catholique de Louvain - ICTEAM - UCL Crypto Group
Address : Place du Levant 3, 1348 Louvain-la-Neuve, BELGIUM
email : firstname.lastname@uclouvain.be
"""

import tools.fingexp as fingexp
import tools.utils as utils
import mathTools.pairing as pair
import gmpy

class PCommitment_Secret_Key(fingexp.FingExp):
    
    def __init__(self,alpha):
        self.alpha = alpha
        
        self.to_fingerprint = ["alpha"]
        self.to_export = {"fingerprint": [],"value": ["alpha"]}

    def load(self, data, fingerprints):
        self.alpha = utils.b64tompz(data["alpha"])
        
    def __str__(self):
        return "Secret Key for Polynomial Commitment: "+str(self.alpha)

class PCommitment_Public_Key(fingexp.FingExp):
    
    def __init__(self,pairing,deg_pol,gVec,hVec):
        self.pairing = pairing
        assert isinstance(self.pairing,pair.Pairing)
        self.deg_pol = deg_pol
        assert deg_pol > 0
        self.gVec = gVec
        self.hVec = hVec
        
        self.to_fingerprint = ["pairing","deg_pol","gVec","hVec"]
        self.to_export = {"fingerprint": [],"value": ["pairing","deg_pol","gVec","hVec"]}

    def load(self, data, fingerprints):
        self.pairing = utils.b64tompz(data["pairing"])
        self.deg_pol = utils.b64tompz(data["deg_pol"])
        self.gVec = utils.b64tompz(data["gVec"])
        self.hVec = utils.b64tompz(data["hVec"])

    def __str__(self):
        return "Public Key for Polynomial Commitment:\n\t "+str(self.Pairing)+"\n\t for polynomial of degree "+str(self.deg_pol)+"\n\t with g vector: "+str(self.gVec)+"\n\t and with h vector: "+str(self.hVec)

    def setup(self,g,h,SK_PC):
        '''
        generates the public key from generators g,h and the secret key SK_PC
        the method (re-)initialize self.gVec and self.hVec
        '''
        alpha = SK_PC.alpha
        gVec = [g]
        hVec = [h]
        for i in range(1,self.deg_pol+1):
            g_prev = gVec[-1]
            h_prev = hVec[-1]
            g_i = alpha*g_prev
            h_i = alpha*h_prev
            gVec.append(g_i)
            hVec.append(h_i)
            
        self.gVec = gVec
        self.hVec = hVec
            
    
    def commit(self,phi_x,phiprime_x=[]):
        '''
        Return a polynomial commitment on the polynomial phi_x eventually using phiprime_x as the randomness polynomial
        '''
        F = self.pairing.Fp
        EFp = self.pairing.EFp
        if phiprime_x == [] :
            for i in range(self.deg_pol+1):
                phiprime_x.append(F.random())
                
        c = EFp.infty
        for i in range(self.deg_pol+1):
            c = c + phi_x[i]*self.gVec[i] + phiprime_x[i]*self.hVec[i]
            
        return c
    
    def open_commitment(self,c,phi_x,phiprime_x):
        '''
        return the opening values of the commitment c, i.e. phi_x and phiprime_x
        '''
        return phi_x,phiprime_x
    
    def verifyPoly(self,c,phi_x,phiprime_x):
        '''
        Check that the commitment c is indeed a commitment on phi_x and phiprime_x
        return True if it is the case
        '''
        pass
    
    def createWitness(self,phi_x,phiprime_x,b):
        '''
        Return a witness w_b for the point (b,phi(b)) to prove latter that phi(b) is the 
        evaluation of phi on b
        '''
        pass
    
    def verifyEval(self, c,b,phi_b,phiprime_b,w_b):
        '''
        Check if c is a commitment on a polynomial phi such that (b,phi_b) belongs
        to the polynomial. The verification uses the witness w_b and the evaluation
        of the polynomial phiprime at b.
        Return True if the verification succeeds.
        This method computes 3 pairings.
        '''
        

class PolynomialCommitment:
    
    def __init__(self,c,PCom_PK):
        self.c = c
        self.PCom_PK = PCom_PK

        self.to_fingerprint = ["PCom_PK","c"]
        self.to_export = {"fingerprint": [],"value": ["PCom_PK","c"]}

    def __eq__(self,other):
        if not isinstance(other,PolynomialCommitment):
            return False
        else :
            return (self.c == other.c and self.PCom_PK == other.PCom_PK)

    def __str__(self):
        #return "PPATSCiphertext :\n"+str(self.PPATSpk)+"\n d :\n"+str(self.d)+"\n c1 :\n"+str(self.c1)+"\n c2 :\n"+str(self.c2)
        return "Polynomial commitment :\n\t"+str(self.c)

    def __repr__(self):
        return self.__str__()

    def __add__(self,e):
        ''' Addition between two Polynomial commitments
            The result is a Polynomial commitment which commits
            on the sum of the initial messages
        '''
        assert isinstance(e,PolynomialCommitment)
        assert self.PCom_PK == e.PCom_PK # commitments built using the same public key
        return PolynomialCommitment(self.c+e.c,self.PCom_PK)
        
    '''
    def addOptim(self,com):
        ECG = self.PCom_PK.h1.ECG
        Jcoord = self.PPATSpk.PPATSpp.Jcoord
        d1 = com.d
        dt = oEC.toTupleEFp(self.d,Jcoord)
        d1t = oEC.toTupleEFp(d1,Jcoord)
        st = oEC.addEFp(ECG,dt,d1t,Jcoord)
        s = oEC.toEFp(ECG,st,Jcoord)
        comp = PPATSCommitment(s,self.PPATSpk)
        return comp
    '''

    def __sub__(self,e):
        assert isinstance(e,PolynomialCommitment)
        return self.__add__(-e)

    def __neg__(self):
        return PolynomialCommitment(-self.c,self.PCom_PK)

    def __mul__(self,a):
        '''multiplication by a scalar a
           The result is a Polynomial Commitment which encrypts and commits on a*m
        '''
        m = gmpy.mpz(1)
        if not isinstance(a, int) and not isinstance(a, long) and not type(a)==type(m):
            raise Exception("Multiplication of a Polynomail Commitment by a non integer, long or mpz")
        else :
            return PolynomialCommitment(a*self.c,self.PCom_PK)

    def __rmul__(self, other):
        return self.__mul__(other)