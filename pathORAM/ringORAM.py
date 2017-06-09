# -*- coding: utf-8 -*-
"""
Created on 2017

Author : Edouard Cuvelier
Affiliation : Université catholique de Louvain - ICTEAM - UCL Crypto Group
Address : Place du Levant 3, 1348 Louvain-la-Neuve, BELGIUM
email : firstname.lastname@uclouvain.be
"""
import tools.fingexp as fingexp
from Crypto.Random.random import randint
from random import sample
import time
import pickle
from cryptoTools.polyCommitment import PolynomialCommitment

def randomPermutation(L):
    '''
    return a random permutation of the list L
    '''
    L_copy = L+[]
    L_perm = []
    #permutation = []
    #p_int = range(len(L))
    while L_copy != [] :
        k = len(L_copy)-1
        r = randint(0,k)
        L_perm.append(L_copy.pop(r))
        #permutation.append(p_int.pop(r))
        
    #return L_perm, permutation
    return L_perm
    
def generatePermTuple(n):
    '''
    generate all permutations of (0,...,n-1) and store them in a Tuple ((perm1),(perm2),...)
    '''
    L = range(n)
    
    def perm(L):
        if len(L) == 1 :
            return [L[0]]
        else :
            Lperm = []
            for i in range(len(L)):
                L_copy = L+[]
                l = L_copy.pop(i)
                pList = perm(L_copy)
                for Li in pList :
                    if not type(Li) == type([]) :
                        Li = [Li]
                    Lperm.append([l]+Li)                
            return Lperm
            
    Lperm = perm(L)
    T = ()
    for Li in Lperm :
        T = T+(tuple(Li),)
        
    return T
                

def pathToIndexList(path,nbChildren,SZ):
    '''
    Given a path of the form a string of integers ranging from 0 to nbChildren,
    convert it to a list of indexes which are the position indexes in a list
    storing the tree containing the path
    For example, the path '021' where nbChildren = 3 and Z = 2 returns the list
    of indexes [0,1,6,7,22,23]
    '''
    assert path[0] == '0'
    n = nbChildren
    k = len(path)
    pow_n = range(k)
    for i in pow_n:
        pow_n[i] = n**i
        
    pow_n.reverse()
    
    #print 'pow_n', pow_n
        
    def prodVec(X,Y):
        assert len(X) == len(Y)
        s = 0
        for i in range(len(X)) :
            s += X[i]*Y[i]
        return s
    
    pathList = []
    for i in range(1,k):
        pathList.append(int(path[i])+1)
        
    indexesList = range(SZ)
    
    #print 'indexesList', indexesList

    for i in range(1,k):
        pr = prodVec(pow_n[-i:],pathList[:i])
        a = SZ*pr
        b = a + SZ
        seg = range(a,b)
        indexesList += seg
        
        #print 'seg', seg
    
    return indexesList
    
def positionToSubPath(position,nbChildren,SZ,depth,subPathDic):
    '''
    Given a position in a list representing the tree,
    return the subpath leading to the node of the tree.
    '''
    # First, look if the entry exists in the dictionary
    try : 
        subpath = subPathDic[position]
    except KeyError :
        pass
    else :
        return subpath
        
    n = nbChildren
    #order = position % Z
    #node_pos = position - order
    
    index = 0
    a = 0
    for i in range(depth+1) :
        b = a + n**i
        if  a*SZ <= position and position < b*SZ :
            index = i
            break
        save_a = a
        a = b
    else :
        print 'i',i
        print 'index', index
        print 'depth',depth
        print 'position',position
        print 'a',save_a
        print 'b',b
        print 'cond', (save_a*SZ <= position and position < b*SZ)
        assert  i != depth-1 # problem!
        
    pivot = a*SZ
    #print 'pivot',pivot
    #print 'index',index
    subPath = ''
    
    for k in range(0,index+1):
        Z_n_i_minus_k = SZ*n**(index-k)
        #remain = (position-pivot) % Z_n_i_minus_k
        #j_k = (position-pivot-remain)/Z_n_i_minus_k
        j_k = (position-pivot)//Z_n_i_minus_k
        pivot = pivot + j_k*Z_n_i_minus_k
        #print 'pivot',pivot
        subPath += str(j_k)
    
    subPathDic[position] = subPath
    return subPath    
    
def randomPath(subpath, nbChildren, depth) :
    '''
    Given a subpath, return a random path containing that subpath
    '''
    if len(subpath) == depth :
        return subpath
    assert len(subpath) <= depth
    
    return randomPath(subpath+str(randint(0,nbChildren-1)),nbChildren,depth)
        
    
class PathORAMTree :
    def __init__(self,blocksList = [], treeID=''):
        '''
        - blocksList is the list of all the blocks of the tree ordered in a canonic way
        - treeID is a string used to identify the tree
        '''
        
        self.treeID = treeID
        self.blocksList = blocksList

        
    def __str__(self):
        return 'Path ORAM Tree '+str(self.treeID)

    def __repr__(self):
        return self.__str__()
        
    def getBlocks(self,indexesList):
        L = []
        for position in indexesList :
            L.append(self.blocksList[position])
        
        #print 'getting blocks of tree :', L
        return L
        
    def writeBlocks(self, L):
        #print 'writing blocks to tree :', L
        
        for position, block in L :
            self.blocksList[position] = block
        
            
class PathORAMTree_for_Polynomial_Commitment(PathORAMTree):
    
    def __init__(self,pC_PK, blocksList = [], treeID=''):
        '''
        - blocksList is the list of all the blocks of the tree ordered in a canonic way
        - treeID is a string used to identify the tree
        '''
        
        self.treeID = treeID
        self.blocksList = blocksList
        self.pC_PK = pC_PK
    
    def getBlocks(self,indexesList):
        ECG = self.pC_PK.pairing.EFp
        L = []
        for position in indexesList :
            b, X = self.blocksList[position]
            c = ECG.uncompress(b,X)
            com = PolynomialCommitment(c, self.pC_PK)
            L.append(com)

        return L
        
    def writeBlocks(self, L):
        
        for position, block in L :
            self.blocksList[position] = block.c.compress()
 
  
class RingORAM :
    
    def __init__(self,POTree, Z= 4, S = 4, A = 4, nbChildren = 2 ,depth = 10, treeHash = '', createDummyBlock = None, rerandomizeBlock = None):
        '''
        - POTree is the Path ORAM tree in which the data will be stored
        - Z is the number of real blocks per node (or bucket)
        - S is the number of dummy blocks per node (or bucket)
        - A is the frequency at which eviction of paths are performed
        - nbChildren is the exact number of children a node must have 
        - depth is the number of levels of the tree
        - treeHash is the Merkle-Damgard hash of the tree
        - createDummyBlock, a method to call when creating dummyBlocks
        - rerandomizeBlock, a method to re-randomize a block
        
        The class initialize the folowing variables:
        - positionMap is a dictionnary used to store the position in which a block
        is currently stored, an item of the dictionnary is of the form 
        {blockID : (position,path)} ; position is set to 'stash', when the 
        block is stored in the client Stash
        - positionList is a list of entries (blockID,path,not_visited) where :
            * the index in positionList corresponds to the index of the list
            the tree
            * blockID and path are set to None when the respective block is a
            dummy block
            * not_visited is a boolean set to True when the block has not yet
            been touched since its last re-randomization
        - clientStash is a dictionary of the form { blockID : block }, it is used
        to store blocks after a query or after a call to self.evictPath()
        - SZ = S+Z the exact number of blocks in each bucket (S+Z)
        - tLoad is the number of blocks in the tree
        - nbNodes is the number of buckets (or nodes) in the tree
        - query_counter keeps track of the number of queries performed, it helps 
        decide when to call self.evictPath(), relatievely to self.A
        - path_counter keeps track of the index of the path to evict when
        self.evictPath() is called. The index is the one of the list :
        - orderedPathList which stores the paths in the reverse lexicographic order
        - sPD is the subpath dictionary that is saved externally to speedup computations
        It indicates, given a position, the subpath leading to it, and thus 
        speeding up any call to positionToSubPath(...).
        '''
        self.POTree = POTree
        self.Z = Z
        self.S = S
        self.A = A
        self.query_counter = 1
        self.path_counter = 0
        self.SZ = S+Z # exact number of blocks in each bucket (S+Z)
        self.nbChildren = nbChildren # exact number of children a bucket has
        self.depth = depth # of the tree
        self.treeHash = treeHash #MD hash of the tree
        
        tLoad = self.SZ
        st = 1
        for i in range(depth):
            st = st*nbChildren
            tLoad += self.SZ*st
            
        self.tLoad = tLoad
        if self.POTree.blocksList == [] :
            self.POTree.blocksList = [None]*self.tLoad
        self.nbNodes = tLoad/self.SZ
        
        self.POTree = POTree
        self.positionList = [(None,None,True)]*self.tLoad # at each position stores entries of the form (blockID,path,not_visited) 
        self.positionMap = {} # stores entries of the form {blockID : (position,path)}
        #self.bucketDic = {} # stores entries of the form {bucketID : [realList,validList]} where realList = [True,False,...] of size S+Z where True accounts for a real block and False for a dummy one. validList = [True,False,...] of size S+Z where True means the blocks has not been visited already
        self.clientStash = {} # stores entries of the form {blockID : block}
        self.dummyStash = [] # List containing dummy blocks
        self.pathList = self.buildPathList()
        self.orderedPathList = self.orderListInReverseLexicographic(self.pathList)
        
        self.hashDic = {}
        self.dummyCounter = 0
        
        # Load the dictionary to speedup computations
        try :
            s = str(self.SZ)+str(self.depth)+str(self.nbChildren)
            f = open('./posDictionaries/positionDic'+s,'r')
            subPathDic = pickle.load(f)
            f.close()
        except IOError :
            s = str(self.SZ)+'_'+str(self.depth)+'_'+str(self.nbChildren)
            f = open('./posDictionaries/positionDic'+s,'w')
            pickle.dump({},f)
            f.close()
            subPathDic = {}
            
        self.sPD = subPathDic
        
        '''
        
        try :
            s = str(self.SZ)
            f = open('./permutations/perm'+s,'r')
            permTup = pickle.load(f)
            f.close()
        except IOError :
            s = str(self.SZ)
            f = open('./permutations/perm'+s,'w')
            permTup = generatePermTuple(self.SZ)
            pickle.dump(permTup,f)
            f.close()
            
            
        self.permTup = permTup
        
        '''
        
        # Below are default methods to use when rerandomizeBlock, createDummyBlock
        # and isADummyBlock methods are not specified
        if rerandomizeBlock == None :
            def fa(block,blockID):
                #print 'rerandomizing block',block
                return 'r-'+block
            self.rerandomizeBlock = fa
        else :
            self.rerandomizeBlock = rerandomizeBlock
            
        if createDummyBlock == None :
            def fb():
                #return 'DB'+(str(randint(0,2**20))), 'dummy block'
                return 'DB', 'dummy block'
            self.createDummyBlock = fb
        else :
            self.createDummyBlock = createDummyBlock
     
    def hashPath(self,path):
        path_copy = path[:-1]
        
        while path_copy != '' :
            self.hashNode(path_copy)
            path_copy = path_copy[:-1]
            
        self.treeHash = self.hashDic['0']
        
    def hashNode(self, subpath):
        
        hashList = []
        for i in range(self.nbChildren):
            hashList.append(self.hashDic[subpath+str(i)])
            
        self.hashDic[subpath] = fingexp.fingerprint([self.hashDic[subpath]]+hashList)
            
        
    def buildPathList(self):
        '''
        this method returns an iterable of the path of self.POTree
        A path is a string of the form '025103...40' where a letter x at index i 
        indicates that the child x of the previous node of level i-1 is in the
        path. The first letter is 0, for the root.
        '''
        
        def genWords(alphabet,length):
            '''
            alphabet is a list of string
            '''
            if length == 1 :
                return alphabet
            else :
                new_words = []
                words = genWords(alphabet,length-1)
                for word in words :
                    for letter in alphabet :
                        new_words.append(letter+word)
                        
                return new_words
                       
        alphabet  = []
        for i in range(self.nbChildren):
            alphabet.append(str(i))
            
        paths = genWords(alphabet,self.depth)
        pathList = []
        for path in paths :
            pathList.append('0'+path)
        return pathList
        
    def orderListInReverseLexicographic(self,L):
        '''
        See the paper [] for the meaning of this order
        '''
        L_copy = L+[]
        for i in range(len(L)):
            L_copy[i] = L_copy[i][::-1]
        L_copy.sort()
        for i in range(len(L)):
            L_copy[i] = L_copy[i][::-1]
        return L_copy
        
    def getDummyBlock(self):
        '''
        Returns a dummy block either by taking one from the dummy stash or by 
        creating a new one.
        '''
        
        if self.dummyStash !=[]:
            #print 'here'
            return self.rerandomizeBlock(self.dummyStash.pop(),None)
        else :
            self.dummyCounter +=1
            return self.createDummyBlock()
        
        #return 'dummy block'
        

        
    def fillupTree(self,blockList):
        '''
        This method assigns blocks to the tree nodes and pad with dummy
        blocks
        We assume here that the tree is empty
        '''
        
        #print 'blockList',blockList
        
        t = self.tLoad
        
        t1 = time.time()
        #permuted_blockList, permutation = randomPermutation(blockList)
        permuted_blockList = randomPermutation(blockList)
        t2 = time.time()
        
        #print 'permuted_blockList',permuted_blockList
        
        new_blockList = []
        while permuted_blockList != [] :
            bucket = []
            i = 0
            while permuted_blockList != [] and i < self.Z :
                bucket.append((permuted_blockList.pop(),True))
                i +=1
                
            while len(bucket)<(self.SZ) :
                bucket.append((self.createDummyBlock(),False))
                
            #permuted_bucket, perm = randomPermutation(bucket) #TODO: time-consuming!
            permuted_bucket= randomPermutation(bucket) #TODO: time-consuming!
            
            new_blockList = permuted_bucket +new_blockList
            
        k = max(t-len(new_blockList),0)
        
        #print 'new_blockList',new_blockList
        
        t3 = time.time()   
        
        for i in range(k):
            new_blockList = [(self.createDummyBlock(),False)]+new_blockList
            
        assert len(new_blockList) == t
        
        #print 'new_blockList',new_blockList
        
        t4 = time.time()
        
        for i in range(0,t,self.SZ):
            bucket = []
            subpath = positionToSubPath(i,self.nbChildren,self.SZ,self.depth,self.sPD)
            for j in range(self.SZ):
                bucket.append(new_blockList[i+j][0])
                
            self.hashDic[subpath] = fingexp.fingerprint(bucket)
            
        self.treeHash = self.hashDic['0']
            
        
        t4b = time.time()
        
        for i in range(t):
            if new_blockList[i][1] == True :
                blockID, block = new_blockList[i][0]
                subpath = positionToSubPath(i,self.nbChildren,self.SZ,self.depth,self.sPD)
                path = randomPath(subpath, self.nbChildren, self.depth+1)
                self.positionList[i] = (blockID,path,True)
                self.positionMap[blockID] = (i,path)
                new_blockList[i] = new_blockList[i][0][1]
                
            else :
                # the block is a dummy one
                new_blockList[i] = new_blockList[i][0]
            
            
            
                   
        t5 = time.time()
        
        L = enumerate(new_blockList)
        #print 'new_blockList',new_blockList
        
        self.POTree.writeBlocks(L)
        
        t6 = time.time()
        
        print 'permutation of blockList:',t2-t1,'\n buckets creation:',t3-t2,'\n dummy block creation:',t4-t3,'\n hashing nodes of the tree:',t4b-t4,'\n filling up of the tree:',t5-t4b, '\n block rerwriting in tree:',t6-t5
    
    def getCandidates(self,indexesList,path):
        '''
        This method returns a list (postion,blockID) of blocks to refill the path.
        The candidate blocks are sought in the client stash and the dummy stash,
        new dummy blocks are created when needed.
        '''
        
        L = indexesList + []
        
        Z = self.Z
        M = {}
        L.reverse()
        #K = self.clientStash.keys()
        #print 'here length of stash is ', len(self.clientStash), len(K)

        for blockID_i in self.clientStash.keys() :
            # This loop fills M that will be used to find good block candidates for filling the buckets
            pos_i, path_i = self.positionMap[blockID_i]
            assert pos_i == 'stash'
            assert path_i != None
            
            if path_i not in M :
                M[path_i] = []
            M[path_i].append(blockID_i)
            
        #print 'M', len(M)
            
                    
        path_copy = path+''
        
        index = 0
        #counter = 0
        new_blockList = []
        
        #tbL = []
        
        while path_copy != '':
            
            new_bucket = []
            for i in range(Z):
                position = L[index]
                candidate = None
                pathList = M.keys()
                for pathb in pathList :
                    if pathb[:len(path_copy)] == path_copy and M[pathb] != [] :
                        candidate = M[pathb].pop()
                        
                        break
                    
                if not candidate == None :
                    new_bucket.append((True,position,candidate)) # here candidate is a blockID
                    #tbL.append(candidate)
                    #counter +=1
                    index +=1
                    
            #if len(new_bucket) < self.Z:
            #    print 'M, new_bucket',M, new_bucket, path_copy
                    
            k = self.SZ-len(new_bucket)
            for i in range(k) :
                position = L[index]
                dummyBlock = self.getDummyBlock()
                new_bucket.append((False,position,dummyBlock))
                index +=1
                
            new_blockList.append((new_bucket))
            path_copy = path_copy[:-1]
        
        #tbL.sort()
        #print 'extracting ', counter, 'blocks from stash', tbL
        return new_blockList
        
    def getBucketCandidates(self,bucket_path):
        '''
        this method returns the real blockID of blocks currently in the client stash
        who might be stored in the bucket 
        '''
        L = []


        for blockID_i in self.clientStash.keys() :
            # This loop fills L that will be used to find good block candidates for filling the buckets
            pos_i, path_i = self.positionMap[blockID_i]
            if bucket_path == path_i[:len(bucket_path)] :
                L.append(blockID_i)
                
        return L
        
    def evictPath(self,buckets_to_reshuffle_list):
        '''
        This method takes the next path to evict in self.orderedPathList and evict it.
        This means that all the blocks along the path are read, stored into the stash
        (for real blocks) and then the path is refilled with blocks from the stash
        and dummy blocks.
        - buckets_to_reshuffle_list is a list containing the ID of the buckets meant
        to be reshuffle by the earlyReshuffle method. As they will be reshuffled in
        the current method, there is no need to reshuffle them later. The list of 
        buckets not to reshuffle later is returned by the method.
        '''
        
        path_to_evict = self.orderedPathList[self.path_counter % len(self.orderedPathList)]
        
        print '\t eviction of path', path_to_evict
        
        indexesList = pathToIndexList(path_to_evict,self.nbChildren,self.SZ)
        niL = []
        for i in range(0,len(indexesList)/self.SZ,self.SZ) :
            realblocklist = []
            dummyblocklist = []
            for j in range(self.SZ):
                index = indexesList[i+j]
                if self.positionList[index][2] == False:
                    pass
                elif self.positionList[index][0] == None :
                    dummyblocklist.append(index)
                else :
                    realblocklist.append(index)
                    
            k =  len(realblocklist)
            if k < self.Z :
                rbucket = realblocklist+dummyblocklist[:(self.Z-k)]
                assert len(rbucket) == self.Z
            elif k == self.Z:
                rbucket = realblocklist
            else :
                assert False
            
            niL += rbucket
                
            
                        
            
        #blockList = self.POTree.getBlocks(indexesList) # Reading the tree
        blockList = self.POTree.getBlocks(niL) # Reading the tree
        #print 'indexesList is', indexesList
        #print 'blockList is', blockList
        bL_copy = blockList+[]
        
        #self.checkSync()
        #print 'checking 1'
        
        buckets_not_to_reshuffle_list = []
        
        for index in buckets_to_reshuffle_list :
            if index in indexesList :
                buckets_not_to_reshuffle_list.append(index)
        
        #added_to_stash = 0
        #tbI = []
        #print 'length of stash', len(self.clientStash)
        for index in niL :
            # This loop retrieves the real blocks from blockList and save them in the stash
            if self.positionList[index][0] == None :
                pass
            else:
                # the block is not a dummy block
                blockID = self.positionList[index][0]
                path_i = self.positionList[index][1]
                block_i = blockList[niL.index(index)]
                
                self.clientStash[blockID] = self.rerandomizeBlock(bL_copy.pop(bL_copy.index(block_i)),blockID)
                self.positionMap[blockID] = 'stash', path_i
                print '(3)updtating position map of ',blockID, 'to ','stash', path_i
                #tbI.append(blockID)
                #added_to_stash += 1
        
                
        #tbI.sort()
        #print added_to_stash,'blocks added to stash', tbI,'new length of stash', len(self.clientStash)
        #print 'dummy stash before increm.', len(self.dummyStash)
        self.dummyStash += bL_copy # Add remaining dummy blocks to the dummy stash
        #print 'dummy stash after increm.', len(self.dummyStash)
        
        new_blockList = self.getCandidates(indexesList,path_to_evict)
        
        #print 'dummy stash after after increm.', len(self.dummyStash)
        
        #print 'candidates got are ', new_blockList
        
        #self.checkSync()
        #print 'checking 2'
        
        nBL = []
        
        #print 'sit1', self.positionList, self.POTree.blocksList
        
        for bucket in new_blockList :
            b_copy = bucket+[]
            b_copy.reverse()
            #print 'bucket to re-shuffle', b_copy
            new_bucket = self.reshuffleBucket(b_copy)

            nBL += new_bucket
            
        #print 'nBL', nBL
        
        self.POTree.writeBlocks(nBL)
        
        #print 'sit2', self.positionList, self.POTree.blocksList
        
        #self.checkSync()
        #print 'checking 3'
        
        self.path_counter +=1
        
        return buckets_not_to_reshuffle_list
    
    def earlyReshuffle(self,buckets_to_reshuffle_list):
        '''
        This method will reshuffle all buckets of buckets_to_reshuffle_list.
        - By doing so, the method might add fitting blocks stored in the client 
        stash into the bucket, up to Z
        - The real blocks already in the bucket, remain there after the shuffle
        - buckets_to_reshuffle_list contains the positions of the first block for
        each bucket
        '''
        print '\t early reshuffling of buckets', buckets_to_reshuffle_list
        
        btrs = buckets_to_reshuffle_list+[]
        btrs.reverse() # begin with the deeper buckets
        
        new_blockList = []
        for first_pos in btrs :
            bucket = range(first_pos,first_pos+self.SZ)
            blocksList = self.POTree.getBlocks(bucket)
            #print 'block list got from tree',blocksList
            new_bucket = []
            b_ID_List = []
            for i in range(self.SZ):
                blockID,path,not_visited = self.positionList[bucket[i]]
                block_i = blocksList[i]
                
                if not blockID == None and not blockID == 'real':
                    b_ID_List.append(blockID)
                    self.clientStash[blockID] = self.rerandomizeBlock(block_i,blockID)
                    nblock = (True,first_pos+len(new_bucket),blockID)
                    #print 'inserting nblock (1)', nblock
                    new_bucket.append(nblock)
                elif blockID == 'real' :
                    pass
                else :
                    """
                    if not block_i == 'dummy block':
                        block_i = 'dummy block'
                    """
                    self.dummyStash.append(block_i)      
                    
            if len(b_ID_List) < self.Z :
                bucket_path = positionToSubPath(first_pos,self.nbChildren,self.SZ,self.depth,self.sPD)
                new_candidates = self.getBucketCandidates(bucket_path)
                for b_ID in new_candidates :
                    if not b_ID in b_ID_List and not len(b_ID_List) >= self.Z :
                        nblock = (True,first_pos+len(b_ID_List),b_ID)
                        #print 'inserting nblock (2)', nblock
                        new_bucket.append(nblock)
                        print 'reinserting',b_ID, 'from stash'
                        b_ID_List.append(b_ID)
                        
            while len(new_bucket)< self.SZ :
                dummyBlock = self.getDummyBlock()
                nblock = (False,first_pos+len(new_bucket),dummyBlock)
                #print 'inserting nblock (3)', nblock
                new_bucket.append(nblock)
            
            perm_bucket = self.reshuffleBucket(new_bucket)
            new_blockList += perm_bucket
            
            
        self.POTree.writeBlocks(new_blockList)
                        
                
    
    def reshuffleBucket(self,bucket):
        '''
        This method randomly shuffles the bucket and update the positionList,
        the positionMap and the clientStash accordingly.
        bucket is a list of tuples (is_real_block, position, blockID_or_dummyBlock)
        We assume all real blocks are stored in the client Stash
        '''
        

        #positionL = []
        
        first_pos = bucket[0][1]
        
        print '\t --> reshuffling bucket', first_pos,'to',first_pos+self.SZ
        
        #for i in range(len(bucket)):
        #    positionL.append(bucket[i][1])
                        
        perm_bucket = randomPermutation(bucket)
            
        for i in range(len(bucket)):
            #position = positionL[i]
            position = first_pos+i
            if perm_bucket[i][0] == True :
                # a real block
                blockID = perm_bucket[i][2]
                block = self.clientStash.pop(blockID)
                #print 're-inserting block',blockID,'from stash'
                old_pos, path = self.positionMap[blockID]
                assert not path == None
                self.positionList[position] = blockID,path,True
                self.positionMap[blockID] = position, path
                print '(1) updtating position map of ',blockID, 'to ',position, path
                perm_bucket[i] = (position,block)
            else :
                # a dummy block
                self.positionList[position] = None,None,True
                perm_bucket[i] = (position,perm_bucket[i][2])
                
        #print 'permuted bucket', perm_bucket
                
        subpath = positionToSubPath(perm_bucket[0][0],self.nbChildren,self.SZ,self.depth,self.sPD)
        B = []
        for i in range(self.SZ):
            B.append(perm_bucket[i][1])
        self.hashDic[subpath] = fingexp.fingerprint(B)
                
        return perm_bucket
                
    def selectIndexes(self,indexesList,position):
        '''
        This method returns the list of indexes of blocks that need to be read
        by selecting them randomly in each bucket among the dummy blocks except
        for the bucket (if any) containing the real block.
        '''
        print position,indexesList

        assert len(indexesList)/self.SZ == self.depth+1
        select_indexesList = []
        reshuffle_bucket_list = [] # keeps track of the bucket that will be reshuffled after the execution of the method
        for i in range(self.depth+1):
            bucket = indexesList[i*self.SZ:(i+1)*self.SZ]
            print 'visiting bucket', bucket
            if position in bucket :
                print self.positionList[position]
                assert self.positionList[position][2] == True
                select_indexesList.append(position)
                self.positionList[position] = 'real',None,False
                
            else :
                randomBlocks = [] # collects the dummy blocks not visited yet
                for index in bucket:
                    if self.positionList[index][0] == None and self.positionList[index][2] == True :
                        # the block is a dummy and not visited yet
                        #print 'appending dummy block', self.positionList[index]
                        randomBlocks.append(index)
                
                # choose randomly a dummy block to read
                r = randint(0,len(randomBlocks)-1)
                randBlock_index = randomBlocks[r]
                select_indexesList.append(randBlock_index)
                self.positionList[randBlock_index] = None,None,False
                    
            count = 0 # keeps track of the number of blocks visited yet in the bucket
            for index in bucket :
                if self.positionList[index][2] == False :
                    count += 1           
            if count > self.S-1 :
                print '!!! Error : counter too big!!!', count
                assert False
            elif count == self.S-1 :
                # this bucket needs to be re-shuffled
                reshuffle_bucket_list.append(indexesList[i*self.SZ])
            print 'counter for bucket', bucket,'equals',count
        
        assert len(select_indexesList) == self.depth+1
        return select_indexesList, reshuffle_bucket_list
            
    def queryBlock(self,blockID):
        '''
        This method returns the block stored in the self.POTree which corresponds
        to the blockID
        
        Doing so, the method might modify all the blocks along one path.
        The blocks are either :
            - rerandomized
            - moved in the stash
            - reassigned in the path
            - replaced by dummy blocks
            
        The method might re-shuffle buckets that have been visited more than
        self.S times
        
        The method recomputes the hash of the tree if some modification occurs
        '''
        assert blockID in self.positionMap
        
        position, path = self.positionMap[blockID]
        assert path in self.pathList
        
        indexesList = pathToIndexList(path,self.nbChildren,self.SZ)
        
        print 'blockID',blockID,' at position', position
        
        print 'seeking path',path, 'returned indexesList',indexesList
        
        assert ((position != 'stash') and (position in indexesList)) or (position == 'stash')
        
        l = len(self.pathList)
        r = randint(0,l-1)
        new_path = self.pathList[r]
        
        # the list of indexes to visit (according to ring ORAM)
        select_indexesList, buckets_to_reshuffle_list = self.selectIndexes(indexesList,position)
        
        print 'select_indexesList are',select_indexesList
        
        blockList = self.POTree.getBlocks(select_indexesList)
        
        #print 'retrieved blocks from the tree are', blockList
        
        #querriedBlock_index = None
        if position == 'stash':
            querriedBlock = self.clientStash[blockID]
        else :
            querriedBlock_index = select_indexesList.index(position)
            querriedBlock = blockList[querriedBlock_index]
            #print 'querriedBlock',querriedBlock
            self.clientStash[blockID] = self.rerandomizeBlock(querriedBlock,blockID)
        
        self.positionMap[blockID] = 'stash', new_path
        print '(2)updtating position map of ',blockID, 'to ','stash', path
        
        #for index in select_indexesList:
        #    self.positionList[index] = None,None,False # False means the dummy blocks have been visited 
        
        #if not querriedBlock_index == None :
        #    self.positionList[querriedBlock_index] = 'real',None,False
        
        buckets_not_to_reshuffle_list = []
        rehashTree = False
        if self.query_counter == 0  :
            # Time to evict a path according to self.A and the previous number of queries
            # buckets_not_to_reshuffle_list is a list of buckets that have been 
            # reshuffled in the evictPath method and so are not to be re-re-shuffled
            # in the earlyReshuffle method
            #print 'stash size before evict path', len(self.clientStash)
            buckets_not_to_reshuffle_list = self.evictPath(buckets_to_reshuffle_list)
            #print 'stash size after evict path', len(self.clientStash)
            rehashTree = True
            
        for bucket in buckets_not_to_reshuffle_list :
            buckets_to_reshuffle_list.remove(bucket)
        
        self.query_counter = (self.query_counter+1) % self.A
        
        if buckets_to_reshuffle_list != [] :
            self.earlyReshuffle(buckets_to_reshuffle_list)
            rehashTree = True
            
        if rehashTree :
            self.hashPath(path)
        
        return querriedBlock
        
    def checkSync(self):
        for i in range(len(self.positionList)) :
            block_id, path_i, b_i = self.positionList[i]
            if not block_id == None :
                if block_id in self.clientStash :
                    pass
                elif not 'dummy block' in self.POTree.blocksList[i] :
                    pass
                else :
                    print '!!! problem !!!', block_id, 'wrongly situated (1)'
                    print i, self.POTree.blocksList[i], self.positionList[i]
                    assert False
                    
        for block_id in self.positionMap.keys() :
            pos, path = self.positionMap[block_id]
            if pos == 'stash' :
                if block_id in self.clientStash : 
                    pass
                else :
                    print '!!! problem !!!', block_id, 'wrongly situated (2)'
                    print  block_id,'\n',self.POTree.blocksList,'\n', self.positionList,'\n',self.positionMap
                    assert False
            else :
                if not 'dummy block' in self.POTree.blocksList[pos]:
                    pass
                else :
                     print '!!! problem !!!', block_id, 'wrongly situated (3)'
                     print  block_id,'\n',self.POTree.blocksList,'\n', self.positionList,'\n',self.positionMap
                     assert False
            
        
##################### Test Example #############################################

def test_example(Z = 3, S = 4, A = 4,nbChildren = 3, depth = 3,nbWords = None):
    
    # create PO Tree
    po_tree = PathORAMTree( treeID = 'test_PO_tree')
    
    RO = RingORAM(po_tree,Z = Z, S=S, A=A , nbChildren = nbChildren, depth = depth)
    
    if nbWords ==  None :
        nbWords = int(RO.tLoad/6)
        
    print 'parameters are\n Z:',Z,'\n depth:', depth,'\n number of children:', nbChildren,'\n number of blocks:', nbWords,'\n theoretic load of the tree:', RO.tLoad
    
    t1 = time.time()
    
    print 'Ring ORAM tree created'
    '''
    L = ['ba','be','bi','bo','bu','ca','ce','ci','co','cu','da','de','di','do','du','fa','fe','fi','fo','fu','ga','ge','gi','go','gu','ha','he','hi','ho','hu','ja','je','ji','jo','ju','ka','ke','ki','ko','ku','la','le','li','lo','lu','ma','me','mi','mo','mu','na','ne','ni','no','nu','pa','pe','pi','po','pu','ra','re','ri','ro','ru','sa','se','si','so','su','ta','te','ti','to','tu','va','ve','vi','vo','vu','wa','we','wi','wo','wu','xa','xe','xi','xo','xu','za','ze','zi','zo','zu']
    blockList  = []
    for i in range(nbWords):
        word = ''
        for j in range(5) :
            syllab = sample(L,1)[0]
            word += syllab
        blockList.append(('Block '+str(i),word))
    '''
    blockList  = []
    for i in range(nbWords):
        blockList.append(('Block '+str(i),'word '+str(i)))
        
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
    
    
def generatePO():
    
    for i in range(2,6):
        for j in range(2,5):
            for k in range(2,9):
                PO,t1,t2 = test_example(i,k,j)
                
                s = str(i)+'_'+str(k)+'_'+str(j)
                f = open('./posDictionaries/positionDic'+s,'w')
                pickle.dump(PO.sPD,f)
                f.close()
                print 'done Z,d,n',i,k,j
                
def testLengthStash(PO,blockList,n):
    dummystashlenght = []
    clientstashlenght = []
    timeL = []
    for i in range(n):
        blockID = sample(blockList,1)[0][0]
        t1 = time.time()
        PO.queryBlock(blockID)
        timeL.append(time.time()-t1)
        dummystashlenght.append(len(PO.dummyStash))
        clientstashlenght.append(len(PO.clientStash))
            
    return dummystashlenght, clientstashlenght, sum(timeL)/n
    