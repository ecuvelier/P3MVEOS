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

class PathORAMTree :
    
    def __init__(self,root = None, bucketList = [], Z = 4, nbChildren = 2 ,depth = 10, treeHash = '', treeID=''):
        '''
        - root, the root of the tree
        - bucketList is the list of all the nodes of the tree
        - Z is the exact size of the bucket
        - nbChildren is the exact number of children a node must have except for 
        the leaf nodes which have none and their parents which have only one
        - depth is the number of level of the tree
        - treeHash is the Merkle-Damgard hash of the tree
        - treeID is a string used to identify the tree
        '''
        self.root = root
        self.bucketList = bucketList
        self.Z = Z # exact number of blocks in each bucket
        self.nbChildren = nbChildren # exact number of children a bucket has
        self.depth = depth # of the tree
        self.treeHash = treeHash #MD hash of the tree
        self.treeID = treeID
        
    def __str__(self):
        return 'Path ORAM Tree '+str(self.treeID)+' with root \n\t'+str(self.root)+'\n\t Z = '+str(self.Z)+'\n\t number of children = '+str(self.nbChildren)+'\n\t depth = '+str(self.depth)+'\n\t and bucket list : \n\t\t'+str(self.bucketList)

    def __repr__(self):
        return self.__str__()
        
    def setup(self,fillingBlockMethod):
        '''
        Build the PO tree by filling each node of the tree by buckets and by
        filling each bucket with self.Z blocks where a block is constructed using
        the fillingBlockMethod argument
        '''
        L = []
        for i in range(self.Z):
            L.append(fillingBlockMethod())
            
        root = PathORAMBucket(self,None,[],L,(0,0),isRoot=True)
        
        self.root = root
        self.bucketList.append(self.root)
        
        def createChildren(bucket, depth):
            if depth == 0 :
                leaf = PathORAMBucket(self,bucket,[],[],(bucket.position[0]+1,0),isLeaf=True)
                bucket.children = [leaf]
                self.bucketList.append(leaf)
                
            else :
                childrenList = []
                for i in range(self.nbChildren):
                    L = []
                    for j in range(self.Z):
                        L.append(fillingBlockMethod())
                        
                    childrenList.append(PathORAMBucket(self,bucket,[],L,(bucket.position[0]+1,i)))
                    
                bucket.children = childrenList    
                    
                for child in childrenList :
                    self.bucketList.append(child)
                    createChildren(child,depth-1)
                    
        createChildren(self.root,self.depth)
                
        
    def isEmpty(self):
        if self.bucketList == [] :
            assert self.root == None
            return True
        else :
            return False
            
    def merkleDamgardHash(self):
        return None

class PathORAMBucket :
    
    def __init__(self,POTree,parent,children,blockList, position, subTreeHash=None, isRoot=False,isLeaf=False):
        '''
        - POTree is the Path ORAM tree in which the bucket is
        - parent is the parent node of the bucket
        - children is a list containing the children nodes of bucket
        - blockList is a list containing the blocks stored in the bucket its size
        is exaclty POTree.Z
        - position is a pair of int (x,y) where 
            - x is the level of the bucket
            - y is the (unique) order among the other siblings
        - subTreeHash is the hash of the sub tree of which bucket is the root
        - isRoot is a boolean whose meaning is obvious
        - isLeaf is a boolean whose meaning is obvious
        '''
        self.POTree = POTree
        self.parent = parent
        self.children = children
        self.blockList = blockList
        self.position = position
        self.subTreeHash = subTreeHash # MD hash of the subtree whose root is self
        self.isRoot = isRoot
        self.isLeaf = isLeaf
        
        if self.isRoot :
            assert self.parent == None
            assert self.isLeaf is False
            self.idNumber = '0'
        else :
            self.idNumber = self.parent.idNumber + str(self.position[1])
        
        if self.isLeaf :
            assert self.children == []
            assert self.blockList == []
            assert self.isRoot is False
            assert self.parent != None
            
    def __str__(self):
        if self.isRoot :
            return 'Root Bucket of the PO tree '+self.POTree.treeID
            
        elif self.isLeaf :
            return 'Leaf Bucket '+str(self.idNumber) +' of the PO tree '+self.POTree.treeID
        else :
            return 'PO Bucket '+str(self.idNumber) +' of the PO tree '+self.POTree.treeID
        
    def __repr__(self):
        return self.__str__()
        
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
        
        for node in self.POTree.bucketList : # follow the path from leaf to root
            nodeID = node.idNumber
            if not len(nodeID) ==  self.POTree.depth + 2 :
                # is not a leaf
                self.positionDic[nodeID] = [('','')]*self.POTree.Z
        
        if creatDummyBlock == None :
            def f():
                return 0
            self.createDummyBlock = f
        else :
            self.createDummyBlock = creatDummyBlock
            
        if rerandomizeBlock == None :
            def fb(block):
                return ('rerand', block)
            self.rerandomizeBlock = fb
        else :
            self.rerandomizeBlock = rerandomizeBlock
        
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
            
        return genWords(alphabet,self.POTree.depth)
        
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
        
        
    def queryBlock(self,blockID):
        '''
        This method returns a block whose Id is blockID. Doing so, the method 
        changes all the buckets (and blocks) that are on the path of the block.
        Also the self.clientStash, the self.positionDic and the self.positionMap
        are modified at the end of the execution.
        '''
        Z = self.POTree.Z        
        
        bucketID,path = self.positionMap[blockID] 
        
        if bucketID == 'stash':
            # the block is stored in the stash
            queriedBlock = self.clientStash[blockID]
            for i in range(len(self.positionDic['stash'])):
                if self.positionDic['stash'][i][0] == blockID :
                    blockOrder = i
                    break
        
        node = self.POTree.root
        
        for i in range(Z) :
            if bucketID == node.idNumber and blockID == self.positionDic[bucketID][i][0]:
                blockOrder = i
                queriedBlock = node.blockList[blockOrder]
                
        path_copy = path
        bucketList = [node] # bucketList will be used afterwards to rewrite blocks into the tree
        
        while path_copy != '' :
            a = path_copy[0]
            child = node.children[int(a)]
            
            for i in range(Z) :
                if bucketID == child.idNumber and blockID == self.positionDic[bucketID][i][0]:
                    blockOrder = i
                    queriedBlock = child.blockList[blockOrder]
                        
                block_i = child.blockList[i]
                block_i_ID, block_i_path = self.positionDic[bucketID][i]
                    
                self.clientStash[block_i_ID] = block_i # add the block to the stash
                self.positionDic['stash'].append((block_i_ID,block_i_path)) # update positionDic accordingly
                self.positionMap[block_i_ID] = ('stash',block_i_path) # update positionMap accordingly
            
            bucketList = [child] +bucketList
            path_copy = path_copy[1:] # remove first letter of path_copy
            
            
        n = len(self.pathList)
        r = randint(0,n-1)
        new_path = self.pathList[r] # Chose a new location for the querried block
        self.positionMap[blockID] = (bucketID,new_path)  # update positionMap accordingly
        self.positionDic[bucketID][blockOrder] = (blockID,new_path) # update positionDic accordingly
        
        
        def getCandidates(BuID):
            '''
            Check in the clientStash if there are candidates blocks that could be
            stored in this bucket (with BuID identifier)
            Return a list of candidates
            '''
            n = len(BuID)
            candidatesList = []
            L = self.positionDic['stash']
            for bloID,path in L :
                if path[:n] == BuID :
                    candidatesList.append(bloID)
            return candidatesList
        
        for bucket in bucketList : # follow the path from leaf to root
            nodeID = bucket.idNumber
            candidates = getCandidates(nodeID)
            
            if len(candidates)< Z :
                for i in range(Z-len(candidates)):
                    DB = self.createDummyBlock()
                    candidates.append(DB)
            
            for i in range(Z):
                # here we store the candidates blocks (previously stored in the stash) into the bucket
                bloID = candidates[i]
                buID, bloPath = self.positionMap[bloID]
                assert buID == 'stash'
                block = self.clientStash[bloID]
                rerand_block = self.rerandomizeBlock(block) 
                bucket.blockList[i] = rerand_block
                
                # update the class variable accordingly of the new position of the block
                self.clientStash.pop(bloID)
                self.positionDic['stash'].remove((bloID,bloPath)) # remove it from the stash
                self.positionDic[nodeID][i] = bloID,bloPath
                self.positionMap[bloID] = nodeID, bloPath                
        
        return queriedBlock
        


##################### Test Example #############################################

def test_example():
    
    # create PO Tree
    po_tree = PathORAMTree(depth = 2, nbChildren = 2, treeID = 'test_PO_tree')
        
    def fbm():
        return randint(0,1000)
    
    po_tree.setup(fbm)
    
    #print po_tree
    
    PO = PathORAM(po_tree)
    
    L = ['ba','be','bi','bo','bu','ca','ce','ci','co','cu','da','de','di','do','du','fa','fe','fi','fo','fu','ga','ge','gi','go','gu','ha','he','hi','ho','hu','ja','je','ji','jo','ju','ka','ke','ki','ko','ku','la','le','li','lo','lu','ma','me','mi','mo','mu','na','ne','ni','no','nu','pa','pe','pi','po','pu','ra','re','ri','ro','ru','sa','se','si','so','su','ta','te','ti','to','tu','va','ve','vi','vo','vu','wa','we','wi','wo','wu','xa','xe','xi','xo','xu','za','ze','zi','zo','zu']
    words  = []
    for i in range(20):
        word = ''
        for j in range(3) :
            syllab = sample(L,1)[0]
            word += syllab
        words.append((i,word))
        
    #print words
        
    PO.fillupStash(words)
    
    print 'client Stash: ',PO.clientStash,'\n'
    print 'position Map: ',PO.positionMap,'\n'
    print 'position Dic: ',PO.positionDic,'\n'
    
    return PO