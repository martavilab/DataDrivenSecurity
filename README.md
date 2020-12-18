# DataDrivenSecurity

Study of some security data standards

## CWE
![picture](/image/logo_cwe.jpg/200x150)

**C**ommon **W**eakness **E**nnumeration is a community-developed list of weaknesses for software and hardware maintained by [MITRE](https://www.mitre.org/).
In this standard each unique weakness is assigned a specific CWE number.       
In order to describe a weakness there is a specific [SCHEMA](https://cwe.mitre.org/documents/schema/).         
So as to study this standard, we can access and download its data from: https://cwe.mitre.org/data/downloads.html. Once we do so, we will be able to see our data structure.         
     
In the following lines we will have a close look at each one of the simple types of the defined schema and other column values that are present in our dataset (our downloaded file) so we can grasp which type of information we will be dealing with (note that they will be presented in the same order they will be found in the dataset).    
    
* ***CWE-ID***     
The CWE identification number.   
* ***Name***      
The name assigned to the CWE-ID.        
* ***Weakness Abstraction*** (*AbstractionEnumeration* in the schema path)      
The CWE entries in the list form a tree of different abstraction layers:   
     ** Pillar      
An example of a a CWE pillar is: CWE-118: Incorrect Access of Indexable Resource ('Range Error').
     ** Class      
Classes are also very abstract entries. Language and technology independent. An example of a CWE class is: CWE-119: Improper Restriction of Operations whithin the Bounds of a Memory Buffer. It is a child of CWE-118.
     ** Base      
Bases are more specific than classes. An example, CWE-787: Out-Of.Bounds-Write and is a child of CWE-119.
     ** Variant      
The most specific types of weaknesses. An example of such is CWE-121: Stack-based Buffer Overflow which is a child of CWE-787.       
* ***Status*** (*StatusEnumeration* in the schema path)     
     
* ***Description***
A written description of the given weakness.   
* ***Extended description***   
Extra written description.   
* ***Related Weaknesses***   




