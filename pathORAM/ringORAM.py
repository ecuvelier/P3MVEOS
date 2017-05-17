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

def pathToIndexList(path,nbChildren,Z):
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
        
    indexesList = range(Z)
    
    #print 'indexesList', indexesList

    for i in range(1,k):
        pr = prodVec(pow_n[-i:],pathList[:i])
        a = Z*pr
        b = a + Z
        seg = range(a,b)
        indexesList += seg
        
        #print 'seg', seg
    
    return indexesList
    
def positionToSubPath(position,nbChildren,Z,depth,subPathDic):
    '''
    Given a position in a list representing the tree,
    return the subpath leading to the node of the tree.
    '''
    
    if not nbChildren in subPathDic :
        subPathDic[nbChildren] = {}
        subPathDic[nbChildren][depth] = {}
        subPathDic[nbChildren][depth][Z] = {}
    elif not depth in subPathDic[nbChildren] :
        subPathDic[nbChildren][depth] = {}
        subPathDic[nbChildren][depth][Z] = {}
    elif not Z in subPathDic[nbChildren][depth] :
        subPathDic[nbChildren][depth][Z] = {}
        
    if position in subPathDic[nbChildren][depth][Z] :
        return subPathDic[nbChildren][depth][Z][position]
    
    n = nbChildren
    #order = position % Z
    #node_pos = position - order
    
    index = 0
    a = 0
    for i in range(depth+1) :
        b = a + n**i
        if  a*Z <= position and position < b*Z :
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
        print 'cond', (save_a*Z <= position and position < b*Z)
        assert  i != depth-1 # problem!
        
    pivot = a*Z
    #print 'pivot',pivot
    #print 'index',index
    subPath = ''
    
    for k in range(0,index+1):
        Z_n_i_minus_k = Z*n**(index-k)
        #remain = (position-pivot) % Z_n_i_minus_k
        #j_k = (position-pivot-remain)/Z_n_i_minus_k
        j_k = (position-pivot)//Z_n_i_minus_k
        pivot = pivot + j_k*Z_n_i_minus_k
        #print 'pivot',pivot
        subPath += str(j_k)
    
    subPathDic[nbChildren][depth][Z][position] = subPath
    return subPath
    
    
def possiblePaths(subPath,nbChildren,depth,subPathDic):
    if not nbChildren in subPathDic :
        subPathDic[nbChildren] = {}
        subPathDic[nbChildren][depth] = {}
    elif not depth in subPathDic[nbChildren] :
        subPathDic[nbChildren][depth] = {}
        
    if subPath in subPathDic[nbChildren][depth] :
        return subPathDic[nbChildren][depth][subPath]
        
    if len(subPath) == depth :
        return [subPath]
        
    L = []
    for i in range(nbChildren):
        L_i = possiblePaths(subPath+str(i),nbChildren,depth)
        L = L+L_i
    
    subPathDic[nbChildren][depth][subPath] = L
    return L
    
    
def randomPath(subpath, nbChildren, depth) :
    
    assert len(subpath) <= depth
    sp_copy = subpath+''
    while len(sp_copy) < depth:
        r = randint(0,nbChildren-1)
        sp_copy += str(r)
    return sp_copy
        
    
class PathORAMTree :
    def __init__(self,blocksList = [], Z = 4, nbChildren = 2 ,depth = 10, treeHash = '', treeID=''):
        '''
        - blocksList is the list of all the blocks of the tree ordered in a canonic way
        - Z is the number of blocks per node (or bucket)
        - nbChildren is the exact number of children a node must have 
        - depth is the number of levels of the tree
        - treeHash is the Merkle-Damgard hash of the tree
        - treeID is a string used to identify the tree
        '''
        
        self.Z = Z # exact number of blocks in each bucket
        self.nbChildren = nbChildren # exact number of children a bucket has
        self.depth = depth # of the tree
        self.treeHash = treeHash #MD hash of the tree
        self.treeID = treeID
        
        tLoad = Z
        st = 1
        for i in range(depth):
            st = st*nbChildren
            tLoad += Z*st
            
        self.tLoad = tLoad
        self.nbNodes = tLoad/Z
        
        if blocksList == [] :
            self.blocksList = [None]*self.tLoad
        else :
            self.blocksList = blocksList
            assert len(self.blocksList) == self.tLoad
        
        
   
    def __str__(self):
        return 'Path ORAM Tree '+str(self.treeID)+' with root \n\t Z = '+str(self.Z)+'\n\t number of children = '+str(self.nbChildren)+'\n\t depth = '+str(self.depth)+'\n\t and bucket list : \n\t\t'+str(self.bucketList)

    def __repr__(self):
        return self.__str__()
        
    """"
    def setup(self,fillingBlockMethod):
        '''
        Build the PO tree by filling each node of the tree with self.Z blocks 
        where a block is constructed using
        the fillingBlockMethod argument
        '''
        
        for i in range(self.tLoad):
            B = fillingBlockMethod()
            self.bucketList.append(B)
    """
            
            
    def getBlocks(self,indexesList):
        L = []
        for position in indexesList :
            L.append(self.blocksList[position])
            
        return L
        
    def writeBlocks(self, L):
        
        for position, block in L :
            self.blocksList[position] = block
            
    def merkleDamgardHash(self):
        return None
 
  
class PathORAM :
    
    def __init__(self,POTree, creatDummyBlock = None, rerandomizeBlock = None, isADummyBlock = None):
        '''
        - POTree is the Path ORAM tree in which the data will be stored
        
        The ethod initialize the folowing variables:
        - positionDic is a dictionnary used to store the position in which a block
        is currently stored, an item of the dictionnary is of the form 
        {bucketID : [(blockID,path),...,] of size Z} ; bucketID is set to 'stash', when the 
        block is stored in the client Stash, in this cas blockID is set to None
        - positionMap is a dictionary of the form {blockID : (bucketID,path)}
        - clientStash is a dictionary { blockID : block } where 
        path is the path on which some blocks must be stored 
        '''
        
        self.POTree = POTree
        self.positionList = [(None,None)]*self.POTree.tLoad # at each position stores entries of the form (blockID,path) 
        self.positionMap = {} # stores entries of the form {blockID : (position,path)}
        self.clientStash = {} # stores entries of the form {blockID : block}
        self.dummyStash = {} # stores entries of the form {blockID : block }
        self.pathList = self.buildPathList()
        
        try :
            s = str(self.POTree.Z)+str(self.POTree.depth)+str(self.POTree.nbChildren)
            f = open('positionDic'+s,'r')
            subPathDic = pickle.load(f)
            f.close()
        except IOError :
            s = str(self.POTree.Z)+'_'+str(self.POTree.depth)+'_'+str(self.POTree.nbChildren)
            f = open('positionDic'+s,'w')
            pickle.dump({},f)
            f.close()
            subPathDic = {}
            
        self.sPD = subPathDic
        
        if rerandomizeBlock == None :
            def fa(block):
                return ('rerand', block)
            self.rerandomizeBlock = fa
        else :
            self.rerandomizeBlock = rerandomizeBlock
            
        if creatDummyBlock == None :
            def fb():
                return 'DB'+(str(randint(0,2**20))), 'dummy block'
            self.createDummyBlock = fb
        else :
            self.createDummyBlock = creatDummyBlock
            
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
        for i in range(self.POTree.nbChildren):
            alphabet.append(str(i))
            
        paths = genWords(alphabet,self.POTree.depth)
        pathList = []
        for path in paths :
            pathList.append('0'+path)
        return pathList
        
    def getDummyBlock(self,dList):
        '''
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
        This method randomly assign blocks to the tree nodes and pad with dummy
        blocks
        We assume here that the tree is empty
        '''
        #Z = self.POTree.Z
        blockL = []
        k = len(blockList)
        t = self.POTree.tLoad
        r1 = t-k # the number of dummyblocks to create
        
        t1 = time.time()
        for blockID, block in blockList:
            blockL.append((blockID, block))
            
        t2 = time.time()
            
        for i in range(r1):
            blockL.append(('DB'+str(i), None))
            
        t3 = time.time()
        
        #print k,t,r1, len(blockDic)
        assert len(blockL) == t # we now have exactly enough blocks to fill up the tree
        
        new_blockList = []
        
        tm1,tm2 = 0,0
        #kBD = blockDic.keys()
        
        for i in range(t):
            t31 = time.time()
            lBD = len(blockL)
            r2 = randint(0,lBD-1)
            randomBlockID, randomBlock = blockL.pop(r2)
            #randomBlock = blockDic.pop(randomBlockID)
            new_blockList.append((i,randomBlock))
            
            t32 = time.time()
            
            subpath = positionToSubPath(i,self.POTree.nbChildren,self.POTree.Z,self.POTree.depth,self.sPD)
            """
            possiblePathsList = possiblePaths(subpath,self.POTree.nbChildren,self.POTree.depth+1)
            l = len(possiblePathsList)
            r2 = randint(0,l-1)
            path = possiblePathsList[r2]
            """
            path = randomPath(subpath, self.POTree.nbChildren, self.POTree.depth+1)
            
            self.positionList[i] = (randomBlockID,path)
            self.positionMap[randomBlockID] = (i,path)
            
            t33 = time.time()
            
            tm1 += t32-t31
            tm2 += t33-t32
            
            if i % (t//64) == 0:
                print round((float(i)/t)*100,2), '% done'
                
        t4 = time.time()
            
        self.POTree.writeBlocks(new_blockList)
        
        t5 = time.time()
        
        print 'blockDic insertion:',t2-t1,'\n dummy block creation:',t3-t2,'\n tree filling:',t4-t3,'\n random block extraction:',tm1/t,'\n path attribution:',tm2/t, '\n block rerwriting in tree:',t5-t4
        
    def getCandidates(self,indexesList,path):
        
        L = indexesList + []
        Z = self.POTree.Z
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
        
        
    def queryBlock(self,blockID):
        '''
        This method returns the block stored in the self.POTree which corresponds
        to the blockID
        
        Doing so, the method modifies all the blocks along the path corresponding
        to the block. The blocks are either :
            - rerandomized
            - moved in the stash
            - reassigned in the path
            - replaced by dummy blocks
        '''
        assert not self.isADummyBlock(blockID)
        
        n = self.POTree.nbChildren
        Z = self.POTree.Z
        position, path = self.positionMap[blockID]
        assert path in self.pathList
        
        #print 'path', path
        
        indexesList = pathToIndexList(path,n,Z)
        
        #print 'indexesList', indexesList
        
        assert ((position != 'stash') and (position in indexesList)) or (position == 'stash')
        
        l = len(self.pathList)
        r = randint(0,l-1)
        new_path = self.pathList[r]
        
        #print 'new_path', new_path
        
        blockList = self.POTree.getBlocks(indexesList)
        
        if position == 'stash':
            querriedBlock = self.clientStash[blockID]
            self.clientStash[blockID] = querriedBlock
        else :
            querriedBlock = blockList[indexesList.index(position)]
            self.positionList[position] = blockID, new_path
        
        self.positionMap[blockID] = position, new_path
            
        for i in range(len(blockList)) :
            block_i = blockList[i]
            pos_i = indexesList[i]
            block_i_ID, path_i = self.positionList[pos_i]
            
            # Update block position and add it to the stash or to the dummystash
            if self.isADummyBlock(block_i_ID) :
                self.dummyStash[block_i_ID] = block_i
                self.positionMap[block_i_ID] = ('dummy stash',path_i)
                
            else :
                self.clientStash[block_i_ID] = block_i
                self.positionMap[block_i_ID] = ('stash',path_i)
                
            self.positionList[pos_i] = (None,None)
            
        new_block_list = self.getCandidates(indexesList,path) # seek candidates to greedily refill the path of the tree
        #print len(new_block_list)
        L = []
        #print 'new_block_list',new_block_list
        #print 'dummystash',self.dummyStash
        
        for position_j, blockID_j in new_block_list :
            if self.isADummyBlock(blockID_j):
                block_j = self.dummyStash.pop(blockID_j)
                L.append((position_j,block_j))
                self.positionMap[blockID_j] = (None,None)
            else :
                block_j = self.clientStash.pop(blockID_j)
                new_block_j = self.rerandomizeBlock(block_j)
                L.append((position_j,new_block_j))
                
            old_pos, path_j  = self.positionMap[blockID_j]
            self.positionList[position_j] = (blockID_j,path_j)
            self.positionMap[blockID_j] =  (position_j,path_j)
            
        
        self.POTree.writeBlocks(L)
            
            
        return querriedBlock
            
        
##################### Test Example #############################################

def test_example(Z = 3, depth = 3,nbChildren = 3,nbWords = None):
    
    # create PO Tree
    po_tree = PathORAMTree(Z = Z, depth = depth , nbChildren = nbChildren , treeID = 'test_PO_tree')
    
    if nbWords ==  None :
        nbWords = int(po_tree.tLoad/6)
        
    print 'parameters are\n Z:',Z,'\n depth:', depth,'\n number of children:', nbChildren,'\n number of blocks:', nbWords,'\n theoretic load of the tree:', po_tree.tLoad
    #def fbm():
    #    return randint(0,1000)
        
    #t0 = time.time()
    
    #po_tree.setup(fbm)
    
    PO = PathORAM(po_tree)
    
    t1 = time.time()
    
    print 'Path ORAM tree created'
    
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
        
    PO.fillupTree(blockList)
    
    t3 = time.time()
    
    print 'Tree filled', t3-t2
    
        
    #PO.randomlyAssignStash()
    #PO.queryBlock(0)
    
    #t4 = time.time()
    
    #print 'Blocks reassigned'
    
    '''
    count = 0
    while len(PO.clientStash) > 10 and count < 10000 :
        PO.queryBlock(0)
        count += 1
        
    print 'count ', count
    '''
    s = str(Z)+'_'+str(depth)+'_'+str(nbChildren)
    f = open('positionDic'+s,'w')
    pickle.dump(PO.sPD,f)
    f.close()
    
    return PO,blockList,t2-t1,t3-t2
    
def generatePO():
    
    for i in range(2,6):
        for j in range(2,5):
            for k in range(2,9):
                PO,t1,t2 = test_example(i,k,j)
                
                s = str(i)+'_'+str(k)+'_'+str(j)
                f = open('positionDic'+s,'w')
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
    