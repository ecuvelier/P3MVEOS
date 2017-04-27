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
    
    print 'pow_n', pow_n
        
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
    
    print 'indexesList', indexesList

    for i in range(1,k):
        pr = prodVec(pow_n[-i:],pathList[:i])
        a = Z*pr
        b = a + Z
        seg = range(a,b)
        indexesList += seg
        
        print 'seg', seg
    
    return indexesList
    
    
class PathORAMTree :
    def __init__(self,bucketList = [], Z = 4, nbChildren = 2 ,depth = 10, treeHash = '', treeID=''):
        '''
        - bucketList is the list of all the nodes of the tree ordered in a canonic way
        - Z is the number of blocks per bucket
        - nbChildren is the exact number of children a node must have 
        - depth is the number of levels of the tree
        - treeHash is the Merkle-Damgard hash of the tree
        - treeID is a string used to identify the tree
        '''
        self.bucketList = bucketList
        self.Z = Z # exact number of blocks in each bucket
        self.nbChildren = nbChildren # exact number of children a bucket has
        self.depth = depth # of the tree
        self.treeHash = treeHash #MD hash of the tree
        self.treeID = treeID
        
        tLoad = Z
        st = 1
        for i in range(depth):
            st = st*nbChildren
            tLoad = tLoad + Z*st
            
        self.tLoad = tLoad
        self.nbNodes = tLoad/Z
   
    def __str__(self):
        return 'Path ORAM Tree '+str(self.treeID)+' with root \n\t Z = '+str(self.Z)+'\n\t number of children = '+str(self.nbChildren)+'\n\t depth = '+str(self.depth)+'\n\t and bucket list : \n\t\t'+str(self.bucketList)

    def __repr__(self):
        return self.__str__()
        
    def setup(self,fillingBlockMethod):
        '''
        Build the PO tree by filling each node of the tree by buckets and by
        filling each bucket with self.Z blocks where a block is constructed using
        the fillingBlockMethod argument
        '''
        
        for i in range(self.tLoad):
            B = fillingBlockMethod()
            self.bucketList.append(B)
            
    def merkleDamgardHash(self):
        return None
        
        
class PathORAM :
    
    def __init__(self,POTree, creatDummyBlock = None, rerandomizeBlock = None):
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
        self.positionDic = {'stash':[]} # stores entries of the form {bucketID : [(blockID,path),...,] of size Z}
        self.positionMap = {} # stores entires of the form {blockID : (bucketID,path)}
        self.clientStash = {} # stores entires of the form {blockID : block }
        self.pathList = self.buildPathList()
        
        if rerandomizeBlock == None :
            def fb(block):
                return ('rerand', block)
            self.rerandomizeBlock = fb
        else :
            self.rerandomizeBlock = rerandomizeBlock
            
        if creatDummyBlock == None :
            def f():
                return 'dummy block'
            self.createDummyBlock = f
        else :
            self.createDummyBlock = creatDummyBlock
        
        
        
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
    
    """
    def fillupStash(self,blockList):
        '''
        Given a blockList (of the form blockId, block = blockList[i]), this
        method fills up the self.clientStash and attributes uniformly randomly 
        a path to each block. The method also sets up the self.positionDic
        '''
        n = len(self.pathList)
        
        assert self.positionDic['stash'] == [] # Stash is not empty do not use this method!
    
        
        for i in range(len(blockList)):
            blockID, block = blockList[i]
            r = randint(0,n-1)
            path = self.pathList[r]
            
            self.positionDic['stash'].append((blockID,path))
            self.positionMap[blockID] = ('stash',path)
            self.clientStash[blockID] = block
    """
    
    def fillupTree(self,blockList):
        '''
        This method randomly assign blocks to the tree nodes and pad with dummy
        blocks
        We assume here that the client stash contains the (real) blocks
        and that the tree is empty
        '''
        #Z = self.POTree.Z
        blockDic = {}
        k = len(blockList)
        t = self.POTree.tLoad
        r = k-t # the number of dummyblocks to create
        for i in range(k):
            blockID, block = blockList[i]
            blockDic[blockID] = block
            
        for i in range(r):
            dumID = 'DB'+str(i)
            dumBlock = self.createDummyBlock()
            blockDic[dumID] = dumBlock
            
        assert len(blockDic) == t # we now have exactly enough blocks to fill up the tree
        
        new_blockList = []
        for i in range(t):
            randomBlockID = sample(blockDic,1)[0]
            randomBlock = blockDic.pop(randomBlockID)
            new_blockList.append(randomBlock)
            
        
    
    