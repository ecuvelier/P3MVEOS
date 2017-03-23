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
        Build the PO tree
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
        position is a pair of int (x,y) where 
            - x is the level of the bucket
            - y is the (unique) order among the other siblings 
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
    
    
class PathORAMBlock :
    
    def __init__(self,element):
        self.element = element
    
    
class PathORAMPositionMap :
    
    def __init__(self,positionDic):
        self.positionDic = positionDic