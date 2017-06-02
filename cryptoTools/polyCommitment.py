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
        
    def hashf(self,L):
        ''' Return a number in Zr computed from a list L of elements
            Assuming that all elements of the list has a fingerprint
        '''
        order = self.pairing.r
        f = fingexp.fingerprint(L)
        z = utils.b64tompz(f)%order
        return z


    def randomPolynomial(self):
        '''
        Return a random polynomial of degree self.deg_pol
        '''
        Fr = self.Fr
        L = []
        for i in range(self.deg_pol+1):
            L.append(Fr.random())
            
        return field.polynom(Fr,L)
    
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
            phiprime_x = self.randomPolynomial()
            
        if len(phiprime_x.coef) < self.deg_pol+1 :
            # Append zeros coef to phiprime_x if its coef list is too short (< deg_pol+1)
            diff = self.deg_pol+1 - len(phiprime_x.coef)
            L = [Fr.zero()]*diff
            new_phiprime_x = field.polynom(Fr,L+phiprime_x.coef)
            phiprime_x = new_phiprime_x
                
        c = EFp.infty
        #TODO: Optimize here
        for i in range(self.deg_pol+1):
            c = c + (phi_x.coef[i].val)*self.gVec[i] + (phiprime_x.coef[i].val)*self.hVec[i]
            
        com = PolynomialCommitment(c,self)
            
        return com, phiprime_x
        
    def rerandomize(self,com,phiprime_x,phisecond_x=None):
        '''
        Return a polynomial commitment with a new randomness polynomial
        '''
        new_phi_x, n_c = self.commit_messages([self.Fr.zero()],phisecond_x)
        new_com, phisecond_x = n_c
        
        rerand_com = new_com+com
        
        return rerand_com, phiprime_x+phisecond_x
        
    def commit_messages(self,messageslist,phiprime_x= None):
        '''
        Commit to a list of messages m_i by building the polynomial prod(x-m_i)
        By default, messages m_j = 0 are append to the list if the lenght of 
        messageslist is smaller than self.deg_pol
        '''
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
            
    
    def open_commitment(self,com,phi_x,phiprime_x):
        '''
        return the opening values of the commitment c, i.e. phi_x and phiprime_x
        '''
        return phi_x,phiprime_x
    
    def verifyPoly(self,com,phi_x,phiprime_x):
        '''
        Check that the commitment c is indeed a commitment on phi_x and phiprime_x
        return True if it is the case
        '''
        EFp = self.pairing.EFp
        
        c_prime = EFp.infty
        #TODO: Optimize here
        for i in range(self.deg_pol+1):
            c_prime = c_prime + (phi_x.coef[i].val)*self.gVec[i] + (phiprime_x.coef[i].val)*self.hVec[i]
            
        return com.c == c_prime
    
    def createWitness(self,phi_x,phiprime_x,b):
        '''
        Return a witness w_b for the point (b,phi(b)) to prove latter that phi(b) is the 
        evaluation of phi on b
        '''

        Fr = self.Fr
        
        phi_b_eval = phi_x.evaluate(b)
        phi_b = field.polynom(Fr,[phi_b_eval])
        x_minus_b = field.polynom(Fr,[Fr.one(),-b])
        psi_x, rem1 = (phi_x-phi_b)/x_minus_b
        
        phiprime_b_eval = phiprime_x.evaluate(b)
        phiprime_b = field.polynom(Fr,[phiprime_b_eval])
        psiprime_x, rem2 = (phiprime_x-phiprime_b)/x_minus_b
                
        assert rem1.iszero()
        assert rem2.iszero()
        
        w_b, psiprime_x = self.commit(psi_x,psiprime_x)
            
        return b, phi_b_eval, phiprime_b_eval, w_b
    
    def verifyEval(self, com, b, phi_b, phiprime_b, w_b):
        '''
        Check if com is a commitment on a polynomial phi such that (b,phi_b) belongs
        to the polynomial. The verification uses the witness w_b and the evaluation
        of the polynomial phiprime at b.
        Return True if the verification succeeds.
        This method computes 3 pairings.
        '''
        
        e = oEC.OptimAtePairing
        Pair = self.pairing
        g = self.gVec[-1]
        h = self.hVec[-1]
        gp = self.gprimeVec[-1]
        gp_alpha = self.gprimeVec[-2]
        
        #TODO: Optimize here
        gprime_b = (b.val)*gp
        t1 = gp_alpha-gprime_b
        u1 = (phi_b.val)*g + (phiprime_b.val)*h
        
        return e(com.c,gp,Pair) == e(w_b.c,t1,Pair)*e(u1,gp,Pair)
        
    def createWitnessBatch(self, phi_x, phiprime_x, B):
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
    
    def verifyEvalBatch(self, com, B, rem1_x, rem2_x, w_B):
        '''
        Check if com is a commitment on a polynomial phi such that (b_j,phi_b_j) belongs
        to the polynomial for each b_j in B. The verification uses the witness w_B 
        and the remainder polynomial rem1_x, rem2_x (see self.createWitnessBatch(...)
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
            
        if len(prod_x_minus_b_j.coef) < self.deg_pol+1 :
            # Append zeros coef to phi_x if its coef list is too short (< deg_pol+1)
            diff = self.deg_pol+1 - len(prod_x_minus_b_j.coef)
            L = [Fr.zero()]*diff
            new_prod_x_minus_b_j = field.polynom(Fr,L+prod_x_minus_b_j.coef)
            prod_x_minus_b_j = new_prod_x_minus_b_j
            
        t1 = EFp2.infty
        #TODO: Optimize here
        for i in range(self.deg_pol+1):
            t1 +=  prod_x_minus_b_j.coef[i].val*self.gprimeVec[i]
        
        
        u1 , rem2_x = self.commit(rem1_x,rem2_x) 
        
        return e(com.c,gp,Pair) == e(w_B.c,t1,Pair)*e(u1.c,gp,Pair)

        
    def queryZKS(self, com, phi_x, phiprime_x, b, b_is_root_of_phi_x, khi_x = None, khiprime_x = None):
        '''
        Returns a non-interactive zero-knowledge proof of knowledge that phi(b)
        = 0 or phi(b) != 0 where phi is the polynomial commited to in com.
        '''
        b, phi_b_eval, phiprime_b_eval, w_b = self.createWitness(phi_x,phiprime_x,b)
        if b_is_root_of_phi_x :
            assert phi_b_eval.iszero()
            return b, w_b, phiprime_b_eval, None
        else :
            #TODO: Optimize here
            z_j = phi_b_eval.val*self.gVec[-1] + phiprime_b_eval.val*self.hVec[-1]
            proof_z_j = self.openingNIZKPOK(com,phi_x,phiprime_x,khi_x,khiprime_x)
            return b, w_b, None, (z_j, proof_z_j)
        
    def openingNIZKPOK(self, com, phi_x, phiprime_x, khi_x = None, khiprime_x = None):
        if khi_x == None :
            khi_x = self.randomPolynomial()
        binding, khiprime_x = self.commit(khi_x,khiprime_x)
        challenge = self.hashf([self,com,binding])
        res_1 = khi_x + challenge*phi_x
        res_2 = khiprime_x + challenge*phiprime_x
        
        return challenge, res_1, res_2
        
    def checkOpeningNIZKPOK(self,com,proof):
        challenge, res_1, res_2 = proof
        A, res_2 = self.commit(res_1,res_2)
        bind_c = A.c-challenge*com.c
        binding = PolynomialCommitment(bind_c,self)
        
        return challenge == self.hashf([self,com,binding])
        
    def verifyZKS(self, com, b, proof):
        '''
        Checks that the NIZKPoK holds meaning that phi(b) = 0 or phi(b) != 0 
        where phi is the polynomial commited to in com.
        '''
        Fr = self.Fr
        e = oEC.OptimAtePairing
        Pair = self.pairing
        gp = self.gprimeVec[-1]
        bp, w_b, phiprime_b_eval, A = proof
        
        if A == None :
            return self.verifyEval(com, b, Fr.zero(), phiprime_b_eval, w_b)
        elif phiprime_b_eval == None :
            #TODO: Optimize here
            z_j, proof_z_j = A
            cond1 = self.checkOpeningNIZKPOK(com,proof_z_j)
            gprime_b = b.val*gp
            gprime_alpha_minus_b = self.gprimeVec[-2]-gprime_b
            cond2 = e(com.c,gp,Pair) == e(w_b.c,gprime_alpha_minus_b,Pair)*e(z_j,gp,Pair)
            return cond1 and cond2
        else :
            return False

class Phone_Number_Commitment_Public_Key(fingexp.FingExp):
    
    def __init__(self,PCommitment_PublicKey):
        self.PC_PK= PCommitment_PublicKey
        assert isinstance(self.PC_PK,PCommitment_Public_Key) 
        
        self.to_fingerprint = ["PC_PK"]
        self.to_export = {"fingerprint": [],"value": ["PC_PK"]}

    def load(self, data, fingerprints):
        self.PC_PK = utils.b64tompz(data["PC_PK"])
     
    def __eq__(self, other):
       return (self.PC_PK == other.PC_PK)

    def __str__(self):
        return "Public Key for Phone Number Commitment using:\n\t "+str(self.PC_PK)
       
        
    def commitPhoneNode(self, G, phoneNumber, listOfOutgoingCalls, phiprime_x = None):
        '''
        Commit to a phoneNumber by creating a commitment on a list of messages 
        listOfOutgoingCalls using self.commit_messages(listOfOutgoingCalls,phiprime_x)
        and then appending phoneNumber*G to the commitment, wher G is a generator
        '''
        
        phi_x, C = self.PC_PK.commit_messages(listOfOutgoingCalls,phiprime_x)
        com, phiprime_x = C
        
        return PolynomialCommitment(phoneNumber.val*G + com.c,self.PC_PK) , phi_x, phiprime_x
        
    def verifyPolyPhoneNumber(self, G, phoneNumber, com, phi_x, phiprime_x):
        '''
        Check that the commitment com is indeed a commitment on phoneNumber,
        phi_x and phiprime_x
        return True if it is the case
        '''
        n_com = PolynomialCommitment(com.c-phoneNumber.val*G,self.PC_PK)
        return self.PC_PK.verifyPoly(n_com,phi_x,phiprime_x)
        
    def verifyEvalPhoneNumber(self, G, phoneNumber, com, b, phi_b, phiprime_b, w_b):
        '''
        Check if com is a commitment on phoneNumber and on a polynomial phi such 
        that (b,phi_b) belongs to the polynomial. The verification uses the 
        witness w_b and the evaluation of the polynomial phiprime at b.
        Return True if the verification succeeds.
        This method computes 3 pairings.
        '''
        n_com = PolynomialCommitment(com.c-phoneNumber.val*G,self.PC_PK)
        return self.PC_PK.verifyEval(n_com,b,phi_b,phiprime_b,w_b)
        
    def verifyEvalBatchPhoneNumber(self, G, phoneNumber, com, B, rem1_x, rem2_x, w_B):
        '''
        Check if com is a commitment on a polynomial phi such that (b_j,phi_b_j) belongs
        to the polynomial for each b_j in B. The verification uses the witness w_B 
        and the remainder polynomial rem1_x, rem2_x (see self.createWitnessBatch(...)
        for their construction).
        Return True if the verification succeeds.
        This method computes 3 pairings.
        '''
        n_com = PolynomialCommitment(com.c-phoneNumber.val*G,self.PC_PK)
        return self.PC_PK.verifyEvalBatch(n_com, B, rem1_x, rem2_x, w_B)
        
    def queryZKSPhoneNumber(self, G, phoneNumber,com, phi_x, phiprime_x, b, b_is_root_of_phi_x, khi_x = None, khiprime_x = None):
        '''
        Returns a non-interactive zero-knowledge proof of knowledge that phi(b)
        = 0 or phi(b) != 0 where phi is the polynomial commited to in com.
        '''
        n_com = PolynomialCommitment(com.c-phoneNumber.val*G,self.PC_PK)
        return self.PC_PK.queryZKS(n_com, phi_x, phiprime_x, b, b_is_root_of_phi_x)
        
    def verifyZKSPhoneNumber(self, G, phoneNumber, com, b, proof):
        '''
        Checks that the NIZKPoK holds meaning that phi(b) = 0 or phi(b) != 0 
        where phi is the polynomial commited to in com.
        '''
        n_com = PolynomialCommitment(com.c-phoneNumber.val*G,self.PC_PK)
        return self.PC_PK.verifyZKS(n_com, b, proof)

class PolynomialCommitment(fingexp.FingExp):
    
    def __init__(self,c,PCom_PK):
        self.c = c
        self.PCom_PK = PCom_PK

        self.to_fingerprint = ["PCom_PK","c"]
        self.to_export = {"fingerprint": [],"value": ["PCom_PK","c"]}
        
    def load(self, data, fingerprints):
        self.c = utils.b64tompz(data["c"])
        self.PCom_PK = utils.b64tompz(data["PCom_PK"])

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