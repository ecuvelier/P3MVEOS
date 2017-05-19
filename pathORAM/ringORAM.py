# -*- coding: utf-8 -*-
"""
Created on 2017

Author : Edouard Cuvelier
Affiliation : Université catholique de Louvain - ICTEAM - UCL Crypto Group
Address : Place du Levant 3, 1348 Louvain-la-Neuve, BELGIUM
email : firstname.lastname@uclouvain.be
"""

from Crypto.Random.random import randint
from random import sample
import time
import pickle

def randomPermutation(L):
    '''
    return a random permutation of the list L
    '''
    L_copy = L+[]
    L_perm = []
    permutation = []
    while L_copy != [] :
        k = len(L_copy)-1
        r = randint(0,k)
        L_perm.append(L_copy.pop(r))
        permutation.append(r)
        
    return L_perm, permutation
    
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
        subpath = subPathDic[nbChildren][depth][SZ][position]
    except KeyError :
        pass
    else :
        return subpath
    
    # Create the appropriate sub-dictionaries
    if not nbChildren in subPathDic :
        subPathDic[nbChildren] = {}
        subPathDic[nbChildren][depth] = {}
        subPathDic[nbChildren][depth][SZ] = {}
    elif not depth in subPathDic[nbChildren] :
        subPathDic[nbChildren][depth] = {}
        subPathDic[nbChildren][depth][SZ] = {}
    elif not SZ in subPathDic[nbChildren][depth] :
        subPathDic[nbChildren][depth][SZ] = {}
        
    
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
    
    subPathDic[nbChildren][depth][SZ][position] = subPath
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
            
        return L
        
    def writeBlocks(self, L):
        
        for position, block in L :
            self.blocksList[position] = block
 
  
class RingORAM :
    
    def __init__(self,POTree, Z= 4, S = 4, A = 4, nbChildren = 2 ,depth = 10, treeHash = '', createDummyBlock = None, rerandomizeBlock = None, isADummyBlock = None):
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
        - isADummyBlock, a method that checks if a block is dummy or not
        
        The class initialize the folowing variables:
        - positionDic is a dictionnary used to store the position in which a block
        is currently stored, an item of the dictionnary is of the form 
        {bucketID : [(blockID,path),...,] of size Z} ; bucketID is set to 'stash', when the 
        block is stored in the client Stash, in this cas blockID is set to None
        - positionMap is a dictionary of the form {blockID : (bucketID,path)}
        - clientStash is a dictionary { blockID : block } where 
        path is the path on which some blocks must be stored 
        '''
        self.POTree = POTree
        self.Z = Z
        self.S = S
        self.A = A
        self.query_counter = 0
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
        
        if rerandomizeBlock == None :
            def fa(block):
                return ('rerand', block)
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
            
        if isADummyBlock == None :
            def fc(blockID):
                if blockID[:2] == 'DB' :
                    return True
                else :
                    return False
            self.isADummyBlock = fc
        else :
            self.isADummyBlock = isADummyBlock
            
        
    def buildPathList(self):
        '''
        this method returns an iterable of the path of self.POTree
        A path is a string of the form '025103...40' where a letter x at index i 
        indicates that the child x of the previous node of level i-1 is in the
        path. The first letter is 0, for the root and the last is always 0 for a
        leaf.
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
        L_copy = L+[]
        for i in range(len(L)):
            L_copy[i] = L_copy[i][::-1]
        L_copy.sort()
        for i in range(len(L)):
            L_copy[i] = L_copy[i][::-1]
        return L_copy
        
    def getDummyBlock(self,dList):
        '''
        #TODO : revise this
        Returns a dummy block either by taking one from the dummy stash or by 
        creating a new one.
        The dummy block ID should not be in dList
        '''
        dummyblock_ID = ''
        if len(self.dummyStash) > 0 :
            L = self.dummyStash.keys()
            while L != [] :
                DB_ID = sample(L,1)[0]
                
                if DB_ID in dList:
                     L.remove(DB_ID)
                else : 
                    dummyblock_ID = DB_ID
                    L = []
                
        if dummyblock_ID != '' :
            dummyblock = self.dummyStash[dummyblock_ID]
            rerand_dummyblock = self.rerandomizeBlock(dummyblock)
            self.dummyStash[dummyblock_ID] = rerand_dummyblock
        else :
            #print 'creating dummy block at time', time.time()
            dummyblock_ID,dummyblock = self.createDummyBlock()
            self.dummyStash[dummyblock_ID] = dummyblock
            
        return dummyblock_ID

        
    def fillupTree(self,blockList):
        '''
        This method assign blocks to the tree nodes and pad with dummy
        blocks
        We assume here that the tree is empty
        '''
        
        #print 'blockList',blockList
        
        t = self.tLoad
        
        t1 = time.time()
        permuted_blockList, permutation = randomPermutation(blockList)
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
                
            permuted_bucket, perm = randomPermutation(bucket)
            
            new_blockList = permuted_bucket +new_blockList
            
        k = max(t-len(new_blockList),0)
        
        #print 'new_blockList',new_blockList
        
        t3 = time.time()   
        
        for i in range(k):
            new_blockList = [(self.createDummyBlock(),False)]+new_blockList
            
        assert len(new_blockList) == t
        
        #print 'new_blockList',new_blockList
        
        t4 = time.time()
        
        for i in range(t):
            if new_blockList[i][1] == True :
                blockID, block = new_blockList[i][0]
                subpath = positionToSubPath(i,self.nbChildren,self.SZ,self.depth,self.sPD)
                path = randomPath(subpath, self.nbChildren, self.depth+1)
                self.positionList[i] = (blockID,path,True)
                self.positionMap[blockID] = (i,path)
                '''
                try :
                    L = self.bucketDic[subpath]
                except KeyError :
                    L = [[True]*(self.SZ),[True]*(self.SZ)]
                
                L[0][i%self.SZ] = True # a real block
                L[1][i%self.SZ] = True # not been visited yet
                
                self.bucketDic[subpath] = L
                '''
                
            else :
                pass
                #self.positionList[i] = (None,None,True)
                '''
                try :
                    L = self.bucketDic[subpath]
                except KeyError :
                    L = [[True]*(self.SZ),[True]*(self.SZ)]
                
                L[0][i%self.SZ] = False # a dummy block
                L[1][i%self.SZ] = True # not been visited yet
                
                self.bucketDic[subpath] = L
                '''
            
            new_blockList[i] = new_blockList[i][0]
                   
        t5 = time.time()      
        
        self.POTree.writeBlocks(enumerate(new_blockList))
        
        t6 = time.time()
        
        print 'permutation of blockList:',t2-t1,'\n buckets creation:',t3-t2,'\n dummy block creation:',t4-t3,'\n filling up of the tree:',t5-t4, '\n block rerwriting in tree:',t6-t5
        
    def getCandidates(self,indexesList,path):
        
        L = indexesList + []
        Z = self.Z
        M = {}
        L.reverse()

        for blockID_i in self.clientStash.keys() :
            pos_i, path_i = self.positionMap[blockID_i]
            assert pos_i == 'stash'
            assert path_i != None
            assert not self.isADummyBlock(blockID_i)
            M[path_i] = blockID_i
                    
        path_copy = path+''
        
        index = 0
        new_blockList = []
        
        dummyList = []
        
        while path_copy != '':
            
            for i in range(Z):
                position = L[index]
                candidate = None
                pathList = M.keys()
                for pathb in pathList :
                    if pathb[:len(path_copy)] == path_copy :
                        candidate = M.pop(pathb)
                        break
                    
                if not candidate == None :
                    new_blockList.append((position,candidate))
                else :
                    #print 'M',M
                    #print 'path',path, path_copy
                    dummyBlock_ID = self.getDummyBlock(dummyList)
                    new_blockList.append((position,dummyBlock_ID))
                    dummyList.append(dummyBlock_ID)

                index +=1
            
            path_copy = path_copy[:-1]
            
        return new_blockList
        
    def evictPath(self,bucket_to_reshuffle_list):
        
        path_to_evict = self.orderedPathList[self.path_counter % len(self.orderedPathList)]
        
        indexesList = pathToIndexList(path_to_evict,self.nbChildren,self.SZ)
        blockList = self.POTree.getBlocks(indexesList)
        bL_copy = blockList+[]
        
        bucket_not_to_reshuffle_list = []
        
        for index in bucket_to_reshuffle_list :
            if index in indexesList :
                bucket_not_to_reshuffle_list.append(index)
                
        for index in indexesList :
            if self.positionList[index][0] != None :
                blockID = self.positionList[index][0]
                path_i = self.positionList[index][1]
                block_i = blockList[index]
                
                self.clientStash[blockID] = bL_copy.pop(bL_copy.index(block_i))
                self.positionMap[blockID] = 'stash', path_i
                
        self.dummyStash += bL_copy # Add remaining dummy blocks to the dummy stash
        
        new_blockList = self.getCandidates(indexesList,path_to_evict)
        
        self.POTree.writeBlocks(new_blockList)
        
        self.path_counter +=1
        
        return bucket_not_to_reshuffle_list
    
    def earlyReshuffle(self,bucket_to_reshuffle_list):
        pass
    
    def reshuffleBucket(self,bucketPosition):
        bucket = self.positionList[bucketPosition:bucketPosition+self.SZ]
        
        permBucket = randomPermutation(bucket)
        
        for i in range(self.SZ):
            blockID = permBucket[i][0]
            path = permBucket[i][1]
            self.positionList[bucketPosition+i]= blockID,path,True
            if not blockID == None :
                self.positionMap[blockID] = bucketPosition+i
        
    
    def selectIndexes(self,indexesList,position):
        
        assert len(indexesList)/self.SZ == self.depth+1
        select_indexesList = []
        reshuffle_bucket_list = []
        for i in range(self.depth+1):
            bucket = indexesList[i*self.SZ:(i+1)*self.SZ]
            randomBlocks = []
            count = 0
            for index in bucket:
                if self.positionList[index][0] == None and self.positionList[index][2] == True :
                    randomBlocks.append(index)
                if self.positionList[index][2] == False :
                    count += 1
            if position in bucket :
                assert self.positionList[position][2] == True
                select_indexesList.append(position)
            else :
                r = randint(0,len(randomBlocks)-1)
                randBlock_index = randomBlocks[r]
                select_indexesList.append(randBlock_index)
            if count == self.S-1 :
                reshuffle_bucket_list.append(indexesList[i*self.SZ])
            elif count > self.S-1 :
                print '!!! Error : counter too big!!!'
                
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
        '''
        assert not self.isADummyBlock(blockID)
        
        position, path = self.positionMap[blockID]
        assert path in self.pathList
        
        indexesList = pathToIndexList(path,self.nbChildren,self.SZ)
        
        assert ((position != 'stash') and (position in indexesList)) or (position == 'stash')
        
        l = len(self.pathList)
        r = randint(0,l-1)
        new_path = self.pathList[r]
        
        select_indexesList,bucket_to_reshuffle_list = self.selectIndexes(indexesList,position)
        
        blockList = self.POTree.getBlocks(select_indexesList)
        
        if position == 'stash':
            querriedBlock = self.clientStash[blockID]
        else :
            querriedBlock = blockList[select_indexesList.index(position)]
        
        self.positionMap[blockID] = 'stash', new_path
        
        for index in select_indexesList:
            self.positionList[index] = None,None,False
            
        if self.query_counter == 0  :
            bucket_not_to_reshuffle_list = self.evictPath(bucket_to_reshuffle_list)
            
        for bucket in bucket_not_to_reshuffle_list :
            bucket_to_reshuffle_list.remove(bucket)
        
        self.query_counter = (self.query_counter+1) % self.A
        
        if bucket_to_reshuffle_list != [] :
            self.earlyReshuffle(bucket_to_reshuffle_list)
        
        return querriedBlock
            
        
##################### Test Example #############################################

def test_example(Z = 3, depth = 3,nbChildren = 3,nbWords = None):
    
    # create PO Tree
    po_tree = PathORAMTree( treeID = 'test_PO_tree')
    
    RO = RingORAM(po_tree,Z = Z, depth = depth , nbChildren = nbChildren)
    
    if nbWords ==  None :
        nbWords = int(RO.tLoad/6)
        
    print 'parameters are\n Z:',Z,'\n depth:', depth,'\n number of children:', nbChildren,'\n number of blocks:', nbWords,'\n theoretic load of the tree:', RO.tLoad
    
    t1 = time.time()
    
    print 'Ring ORAM tree created'
    
    L = ['ba','be','bi','bo','bu','ca','ce','ci','co','cu','da','de','di','do','du','fa','fe','fi','fo','fu','ga','ge','gi','go','gu','ha','he','hi','ho','hu','ja','je','ji','jo','ju','ka','ke','ki','ko','ku','la','le','li','lo','lu','ma','me','mi','mo','mu','na','ne','ni','no','nu','pa','pe','pi','po','pu','ra','re','ri','ro','ru','sa','se','si','so','su','ta','te','ti','to','tu','va','ve','vi','vo','vu','wa','we','wi','wo','wu','xa','xe','xi','xo','xu','za','ze','zi','zo','zu']
    blockList  = []
    for i in range(nbWords):
        word = ''
        for j in range(5) :
            syllab = sample(L,1)[0]
            word += syllab
        blockList.append(('Block '+str(i),word))
        
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
    