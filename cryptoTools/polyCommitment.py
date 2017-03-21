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
import mathTools.field as field
import mathTools.otosEC as oEC
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
    
    def __init__(self,pairing,deg_pol,gVec=[],hVec=[],gprimeVec=[]):
        self.pairing = pairing
        self.Fr = field.Field(self.pairing.r)
        assert isinstance(self.pairing,pair.Pairing)
        self.deg_pol = deg_pol
        assert deg_pol > 0
        self.gVec = gVec
        self.hVec = hVec
        self.gprimeVec = gprimeVec

        
        self.to_fingerprint = ["pairing","deg_pol","gVec","hVec","gprimeVec"]
        self.to_export = {"fingerprint": [],"value": ["pairing","deg_pol","gVec","hVec","gprimeVec"]}

    def load(self, data, fingerprints):
        self.pairing = utils.b64tompz(data["pairing"])
        self.deg_pol = utils.b64tompz(data["deg_pol"])
        self.gVec = utils.b64tompz(data["gVec"])
        self.hVec = utils.b64tompz(data["hVec"])
        self.gprimeVec = utils.b64tompz(data["gprimeVec"])    
        
    def __eq__(self, other):
       return (self.deg_pol == other.deg_pol and self.gVec == other.gVec and self.hVec == other.hVec  and self.gprimeVec == other.gprimeVec )

    def __str__(self):
        return "Public Key for Polynomial Commitment:\n\t "+str(self.pairing)+"\n\t for polynomial of degree "+str(self.deg_pol)+"\n\t with g vector: "+str(self.gVec)+"\n\t and with h vector: "+str(self.hVec)+"\n\t and with gprime vector: "+str(self.gprimeVec)

    def setup(self,g,h,gp,SK_PC):
        '''
        generates the public key from generators g,h and the secret key SK_PC
        the method (re-)initialize self.gVec and self.hVec
        '''
        alpha = SK_PC.alpha
        gVec = [g]
        hVec = [h]
        gprimeVec = [gp]
        for i in range(1,self.deg_pol+1):
            g_prev = gVec[-1]
            h_prev = hVec[-1]
            gp_prev = gprimeVec[-1]
            g_i = alpha*g_prev
            h_i = alpha*h_prev
            gp_i = alpha*gp_prev
            gVec.append(g_i)
            hVec.append(h_i)
            gprimeVec.append(gp_i)
        
        gVec.reverse()
        hVec.reverse()
        gprimeVec.reverse()
        self.gVec = gVec
        self.hVec = hVec
        self.gprimeVec = gprimeVec            
    
    def commit(self,phi_x,phiprime_x= None):
        '''
        Return a polynomial commitment on the polynomial phi_x eventually using phiprime_x as the randomness polynomial
        '''
        #Fp = self.pairing.Fp
        Fr = self.Fr
        EFp = self.pairing.EFp
        #order = self.pairing.r
        
        assert len(phi_x.coef) <= self.deg_pol+1
        if len(phi_x.coef) < self.deg_pol+1 :
            # Append zeros coef to phi_x if its coef list is too short (< deg_pol+1)
            diff = self.deg_pol+1 - len(phi_x.coef)
            L = [Fr.zero()]*diff
            new_phi_x = field.polynom(Fr,L+phi_x.coef)
            phi_x = new_phi_x
        
        if phiprime_x == None :
            L = []
            for i in range(self.deg_pol+1):
                L.append(Fr.random())
            
            phiprime_x = field.polynom(Fr,L)
            
        if len(phiprime_x.coef) < self.deg_pol+1 :
            # Append zeros coef to phiprime_x if its coef list is too short (< deg_pol+1)
            diff = self.deg_pol+1 - len(phiprime_x.coef)
            L = [Fr.zero()]*diff
            new_phiprime_x = field.polynom(Fr,L+phiprime_x.coef)
            phiprime_x = new_phiprime_x
                
        c = EFp.infty
        for i in range(self.deg_pol+1):
            c = c + (phi_x.coef[i].val)*self.gVec[i] + (phiprime_x.coef[i].val)*self.hVec[i]
            
        return c, phiprime_x
        
    def commit_messages(self,messageslist,phiprime_x= None):
        assert len(messageslist)<=self.deg_pol
        
        Fr = self.Fr
        mlist_copy = messageslist+[]
        if len(messageslist) < self.deg_pol :
            for i in range(self.deg_pol-len(messageslist)):
                mlist_copy.append(Fr.zero())
                
        phi_x = field.polynom(Fr,[Fr.one()])
        for i in range(self.deg_pol):
            x_minus_m_i = field.polynom(Fr,[Fr.one(),-mlist_copy[i]])
            phi_x = phi_x*x_minus_m_i
            
        return phi_x, self.commit(phi_x,phiprime_x)
            
    
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
        EFp = self.pairing.EFp
        #order = self.pairing.r
        
        c_prime = EFp.infty
        for i in range(self.deg_pol+1):
            c_prime = c_prime + (phi_x.coef[i].val)*self.gVec[i] + (phiprime_x.coef[i].val)*self.hVec[i]
            
        return c == c_prime
    
    def createWitness(self,phi_x,phiprime_x,b):
        '''
        Return a witness w_b for the point (b,phi(b)) to prove latter that phi(b) is the 
        evaluation of phi on b
        '''
        #Fp = self.pairing.Fp
        Fr = self.Fr
        #EFp = self.pairing.EFp
        #order = self.pairing.r
        #w_b = EFp.infty
        
        phi_b_eval = phi_x.evaluate(b)
        
        phi_b = field.polynom(Fr,[phi_b_eval])
        x_minus_b = field.polynom(Fr,[Fr.one(),-b])
        #print 'x_minus_b ', x_minus_b
        #print '(phi_x-phi_b )', (phi_x-phi_b)
        psi_x, rem1 = (phi_x-phi_b)/x_minus_b
        
        phiprime_b_eval = phiprime_x.evaluate(b)#
        #print 'phiprime_b_eval', phiprime_b_eval<order
        phiprime_b = field.polynom(Fr,[phiprime_b_eval])
        psiprime_x, rem2 = (phiprime_x-phiprime_b)/x_minus_b
        
        '''
        print 'psi_x ',psi_x
        print 'psiprime_x ',psiprime_x
        print 'rem1 ',rem1
        print 'rem2 ',rem2
        '''
        
        assert rem1.iszero()
        assert rem2.iszero()
        
        '''
        L = [Fr.zero()]+psi_x.coef
        psi_x = field.polynom(Fr,L)
        K = [Fr.zero()]+psiprime_x.coef
        psiprime_x = field.polynom(Fr,K)
        
        
        for i in range(self.deg_pol+1):
            #w_b = w_b + (psi_x.coef[i].val%order)*self.gVec[i] + (psiprime_x.coef[i].val%order)*self.hVec[i]
            w_b = w_b + (psi_x.coef[i].val)*self.gVec[i] + (psiprime_x.coef[i].val)*self.hVec[i]
        '''
        w_b, psiprime_x = self.commit(psi_x,psiprime_x)
            
        return b, phi_b_eval, phiprime_b_eval, w_b
    
    def verifyEval(self, c,b,phi_b,phiprime_b,w_b):
        '''
        Check if c is a commitment on a polynomial phi such that (b,phi_b) belongs
        to the polynomial. The verification uses the witness w_b and the evaluation
        of the polynomial phiprime at b.
        Return True if the verification succeeds.
        This method computes 3 pairings.
        '''
        
        #order = self.pairing.r
        
        e = oEC.OptimAtePairing
        Pair = self.pairing
        g = self.gVec[-1]
        h = self.hVec[-1]
        gp = self.gprimeVec[-1]
        gp_alpha = self.gprimeVec[-2]
        
        gprime_b = (b.val)*gp
        t1 = gp_alpha-gprime_b
        u1 = (phi_b.val)*g + (phiprime_b.val)*h
        
        return e(c,gp,Pair) == e(w_b,t1,Pair)*e(u1,gp,Pair)
        
    def createWitnessBatch(self,phi_x,phiprime_x,B):
        '''
        Return a witness w_b for the list of points (b_j,phi(b_j)) where b_j in 
        the list B to prove latter that each phi(b_j) is the evaluation of phi on b_j
        '''
        Fr = self.Fr

        prod_x_minus_b_j = field.polynom(Fr,[Fr.one()])
        for b_j in B :
            x_minus_b_j = field.polynom(Fr,[Fr.one(),-b_j])
            prod_x_minus_b_j *= x_minus_b_j

        psi_x, rem1_x = phi_x/prod_x_minus_b_j
        psiprime_x, rem2_x = phiprime_x/prod_x_minus_b_j
        
        w_B, psiprime_x = self.commit(psi_x,psiprime_x)
            
        return B, rem1_x, rem2_x, w_B
    
    def verifyEvalBatch(self,c, B, rem1_x, rem2_x, w_B):
        '''
        Check if c is a commitment on a polynomial phi such that (b_j,phi_b_j) belongs
        to the polynomial for each b_j in B. The verification uses the witness w_B 
        and the remainder polynomial Rx_1,Rx_2 (see self.createWitnessBatch(...)
        for their construction).
        Return True if the verification succeeds.
        This method computes 3 pairings.
        '''
        Fr = self.Fr
        e = oEC.OptimAtePairing
        Pair = self.pairing
        gp = self.gprimeVec[-1]
        EFp2 = gp.ECG

        
        prod_x_minus_b_j = field.polynom(Fr,[Fr.one()])
        for b_j in B :
            x_minus_b_j = field.polynom(Fr,[Fr.one(),-b_j])
            prod_x_minus_b_j *= x_minus_b_j
            
        t1 = EFp2.infty
        for i in range(self.deg_pol+1):
            t1 +=  prod_x_minus_b_j.coef[i].val*self.gprimeVec[i]
        
        
        u1 , rem2_x = self.commit(rem1_x,rem2_x) 
        
        return e(c,gp,Pair) == e(w_B,t1,Pair)*e(u1,gp,Pair)

        
    def queryZKS(self,c,b):
        '''
        Returns a non-interactive zero-knowledge proof of knowledge that phi(b)
        = 0 or phi(b) != 0 where phi is the polynomial commited to in c.
        '''
        return None
        
    def verifyZKS(self,c,b,proof):
        '''
        Checks that the NIZKPoK holds meaning that phi(b) = 0 or phi(b) != 0 
        where phi is the polynomial commited to in c.
        '''
        return None
        

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