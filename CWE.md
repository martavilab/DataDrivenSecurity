## CWE
<img src="/image/logo_cwe.jpg" width="200">
**C**ommon **W**eakness **E**nnumeration is a community-developed list of weaknesses for software and hardware maintained by [MITRE](https://www.mitre.org/).
In this standard each unique weakness is assigned a specific CWE number.       
In order to describe a weakness there is a specific [SCHEMA](https://cwe.mitre.org/documents/schema/).         
So as to study this standard, we can access and download its data from: https://cwe.mitre.org/data/downloads.html. Alternatively: https://github.com/Whamo12/fetch-cwe-list. Once we do so, we will be able to see our data structure.         
     
In the following lines we will have a close look at each one of the simple types of the defined schema and other column values that are present in our dataset (our downloaded file) so we can grasp which type of information we will be dealing with (note that they will be presented in the same order they will be found in the dataset).    
    
* ***CWE-ID***     
The CWE identification number.   
   
* ***Name***      
The name assigned to the CWE-ID.       
   
* ***Weakness Abstraction*** (see *AbstractionEnumeration* in the schema path)      
The CWE entries in the list form a tree of different abstraction layers:   
     - **Pillar**     
An example of a a CWE pillar is: CWE-118: Incorrect Access of Indexable Resource ('Range Error').
     - **Class**      
Classes are also very abstract entries. Language and technology independent. An example of a CWE class is: CWE-119: Improper Restriction of Operations whithin the Bounds of a Memory Buffer. It is a child of CWE-118.
     - **Base**      
Bases are more specific than classes. An example, CWE-787: Out-Of Bounds-Write and is a child of CWE-119.
     - **Variant**      
The most specific types of weaknesses. An example of such is CWE-121: Stack-based Buffer Overflow which is a child of CWE-787.       
* ***Status*** (see *StatusEnumeration* in the schema path)     
Status values that an entity (view, category, weakness) can have:
     * **Deprecated**   
     Entity has been removed from CWE, likely because it was a duplicate or was created in error.    
     * **Obsolete**
     When an entity is still valid but no longer is relevant, likely because it has been superceded by a more recent entity.    
     * **Incomplete**   
     The entity does not have all important elements filled, and there is no guarantee of quality.   
     * **Draft**   
     Entity has all important elements filled, and critical elements such as Name and Description are reasonably well-written; the entity may still have important problems or gaps.    
     * **Usable**   
     Refers to an entity that has received close, extensive review, with critical elements verified.    
     * **Stable**   
     All important elements have been verified, and the entry is unlikely to change significantly in the future.    
     
Status enumeration might change over time.
* ***Description***   
A written description of the given weakness.   
   
* ***Extended description***   
Extra written description (optional).  
   
* ***Related Weaknesses***  (see *RelatedWeaknessesType* in the schema path)   
To refer to other weaknesses that differ only in their level of abstraction. It contains one or more elements each of which contain the nature of the relation.   
The Nature of a weakness (*RelatedNatureEnumeration* type in the schema path) is directly related to the abstraction layer it has. The different natures are the following:   
     - **ChildOf**   
     Denotes a related weakness at a higher level of abstraction. Therefore, for example, a Pillar cannot have a nature of this kind.   
     - **ParentOf**   
     Denotes a related weakness at a lower level of abstraction. Therefore, for example, a Variant cannot have a nature of this kind.   
     - **StartsWith**, **CanPrecede** & **CanFollow**   
     Used to denote weaknesses that are part of a chaining structure.   
     - **RequiredBy** & **Requires**   
     Used to denote a weakness that is part of a composite weakness structure.   
     - **CanAlsoBe**   
     Denotes a weakness that, in the proper environment and context, can also be perceived as the target weakness. Note that it is not necessarily reciprocal.   
     - **PeerOf**   
     To show some similarity with the target weakness yet no other type of relationship can be stated.   
     
We can see that this field is composed of 3 or 4 subfields: <Nature, CWE_ID, View_ID, (Ordinal)>.    

*Nature* subfield will be one of the previously seen, which will point to the target weakness, which will be decribed by the *CWE_ID*.    

*View_ID* subfield specifies which view the given relationship is relevant to. It is a unique identifier of an individual view element to which this relationship pertains. A view represents a perspective with which one might look at the weaknesses in the catalog. There are three different types of views: graphs, explicit slices, and implicit slices. An example of this would be CWE-630: Weaknesses Examined by SAMATE and CWE-658: Weaknesses found in the C Language. Therefore, we could conclude they are the different approaches there are given a specific weakness.   

Finally, we could have the optional subview *Ordinal* which can only be "Primary".   
   
***Weakness Ordinalities***(see *WeaknessOrdinalitiesType* in the schema path)   










