# -*- coding: utf-8 -*-
"""
Created on 2017

Author : Edouard Cuvelier
Affiliation : Université catholique de Louvain - ICTEAM - UCL Crypto Group
Address : Place du Levant 3, 1348 Louvain-la-Neuve, BELGIUM
email : firstname.lastname@uclouvain.be
"""

class PathORAMTree :
    
    def __init__(self,root,bucketList,Z,nbChildren,depth,treeHash,treeID=''):
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
            L.append(fillingBlockMethod)
            
        root = PathORAMBucket(self,None,[],L,(0,1),isRoot=True)
        
        self.root = root
        self.bucketList.append(self.root)
        
        def createChildren(bucket, depth):
            if depth == 0 :
                leaf = PathORAMBucket(self,bucket,[],[],(bucket.position[0]+1,1),isLeaf=True)
                bucket.children = [leaf]
                self.bucketList.append(leaf)
                
            else :
                childrenList = []
                for i in range(self.nbChildren):
                    L = []
                    for j in range(self.Z):
                        L.append(fillingBlockMethod)
                        
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
            return 'Root Bucket of the Path ORAM tree'
        else :
            return 'Path ORAM Bucket with id '+str(self.idNumber) +' of the Path ORAM tree '+self.POTree.root.treeID
        
    def __repr__(self):
        return self.__str__()
        
    def merkleDamgardHash(self):
        return None
        
class PathORAM :
    
    def __init__(self,POTree, positionDic, clientStash):
        '''
        - POTree is the Path ORAM tree in which the data will be stored
        - positionDic is a dictionnary used to store the position in which a block
        is currently stored, an item of the dictionnary is of the form 
        {blockID : (path,bucketID,blockOrder)}
        - clientStash is a list of pair (path,block) where path is the path on 
        which block must be stored 
        '''
        self.POTree = POTree
        self.positionDic = positionDic # store entries of the form {blockID : (path,bucketID,blockOrder)}
        self.clientStash = clientStash
        self.pathList = self.buildPathList()
        
    def buildPathList(self):
        '''
        this method returns an iterable of the path of self.POTree
        A path is a string of the form '025103...40' where a letter x at index i 
        indicates that the child x of the previous node of level i-1 is in the
        path. The first letter is 0, for the root and the last is always 0 for a
        leaf.
        '''
        return None
        
    def queryBlock(self,blockID):
        '''
        This method returns a block whose Id is blockID. Doing so, the method 
        changes all the buckets (and blocks) that are on the path of the block.
        Also the self.clientStash is modified at the end of the execution. 
        '''
        return None
        
    def fillupStash(blockList):
        '''
        Given a blockList, this method fills up the self.clientStash and attributes
        uniformly randomly a path to each block.
        '''
        pass
        
        