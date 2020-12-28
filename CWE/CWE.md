# CWE
<img src="CWE/image/logo_cwe.jpg" width="200">   

**C**ommon **W**eakness **E**nnumeration is a community-developed list of weaknesses for software and hardware maintained by [MITRE](https://www.mitre.org/).
In this standard each unique weakness is assigned a specific CWE number.       
In order to describe a weakness there is a specific [SCHEMA](https://cwe.mitre.org/documents/schema/).     
The CWE List and associated classification taxonomy serve as a language that can be used to identify and describe these weaknesses in terms of CWEs.     
So as to study this standard, we can access and download its data from: https://cwe.mitre.org/data/downloads.html <sub>(link 1)</sub>. Alternatively: https://github.com/Whamo12/fetch-cwe-list <sub>(link 2)</sub>. Once we do so, we will be able to see our data structure.         
     
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
The Nature of a weakness (see *RelatedNatureEnumeration* type in the schema path) is directly related to the abstraction layer it has. The different natures are the following:   
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

   Finally, we could have the optional subview *Ordinal* (see *WeaknessOrdinalitiesType* in the schema path) which can only be "Primary" since it is used to determine if this relationship is the primary ChildOf relationship for this weakness for a given View_ID.   
   
* ***Weakness Ordinalities***    
Indicates potential ordering relationships with other weaknesses.      
Elements:   
     * *Ordinality* (required)   
     Identifies whether the weakness has a **primary**, **resultant**, or **indirect** relationship.    
     It is important to note that it is possible for the same entry to be primary in some instances and resultant in others.       
     * *Description* (optional)   
     Contains the context in which the relationship exists.   
<sub>Not in link 2</sub>    
   
* ***Applicable platforms*** (see *ApplicablePlatformsType* in the schema path)   
The **languages**, **operating systems**, **architectures**, and **technologies** in which a given weakness could appear. The most common described one is Language.   
Each of these have some atributes like: *Class*, *Name* and:
     * *Prevalence* (required)   
     Identifies the regularity with which the weakness is applicable to that platform.      
     
   Note that when providing an operating system name, an optional Common Platform Enumeration (CPE) identifier can be used to a identify a specific OS.     
    
* ***Background details*** (see *BackgroundDetailsType* in the schema path)      
Contains one or more elements, each of which contains information that is relevant but not related to the nature of the weakness itself.     
     
* ***Alternate Terms*** (see *AlternateTermsType* in the schema path)   
To indicate one or more other names used to describe a given weakness.   
Required elements: 
     * *Term* (contains the actual alternate term)   
     * *Description* (context for each alternate term by which this weakness may be known).   
     
   <sub>Not in link 2</sub>    
     
* ***Modes Of Introduction*** (see *ModesOfIntroductionType* in the schema path)   
To provide information about how and when a given weakness may be introduced. If there are multiple possible introduction points, then a separate Introduction element should be included for each.    
Elements:
     * *Phase* (required)    
     Identifies the point in the product life cycle at which the weakness may be introduced. Examples of it would be: 'Implementation' or 'Architecture and Design'.    
     * *Note* (optional)    
     Identifies the typical scenarios under which the weakness may be introduced during the given phase.    
     
* ***Exploitation Factors*** (see *ExploitationFactorsType* in the schema path)   
Conditions or factors that could increase the likelihood of exploit for this weakness.    
     
   <sub>Not in link 2</sub>    
     
* ***Likelihood of Exploit***    
How likely a weakness is to be exploited if exposed. Appropriate values are **Low**, **Medium**, or **High**.    
    
* ***Common Consequences*** (see *CommonConsequencesType* in the schema path)   
To specify individual consequences associated with a weakness.   
Elements:
     * *Scope* (required)   
     Identifies the security property that is violated.    
     * *Impact* (optional)    
     Describes the technical impact that arises if an adversary succeeds in exploiting this weakness.     
     * *Likelihood* (optional)    
     How likely the specific consequence is expected to be seen relative to the other consequences.     
     * *Note* (optional)     
     Additional commentary about a consequence.   
     <sub> Optional Consequence_ID attribute for internal team use to uniquely identify examples that are repeated across any number of individual weaknesses. Its value matches the following format: CC-1. </sub>    
    
* ***Detection Methods*** (see *DetectionMethodsType* in the schema path)   
To identify methods that may be employed to detect this weakness, including their strengths and limitations.     
Elements:    
     * *Method* (required)    
     Identifies the particular detection method being described.    
     * *Description* (required)    
     Provides some context of how this method can be applied to a specific weakness.     
     * *Effectiveness* (optional)   
     How effective the detection method may be in detecting the associated weakness. This assumes the use of best-of-breed tools, analysts, and methods. There is limited consideration for financial costs, labor, or time.     
     * *Effectiveness_Notes* (optional)    
     Additional discussion of the strengths and shortcomings of this detection method.     
     <sub>Optional Detection_Method_ID attribute for internal team use to uniquely identify methods that are repeated across any number of individual weaknesses. Its value matches the following format: DM-1. </sub>   
     
   <sub>Not in link 2</sub>    
     
* ***Potential Mitigations*** (see *PotentialMitigationsType* in the schema path)   
Describes potential mitigations associated with a weakness.     
It contains one or more Mitigation elements, which each represent individual mitigations for the weakness.     
Elements:    
     * *Phase*    
     Indicates the development life cycle phase during which this particular mitigation may be applied.     
     * *Strategy*    
     Describes a general strategy for protecting a system to which this mitigation contributes.     
     * *Effectiveness*    
     Summarizes how effective the mitigation may be in preventing the weakness.     
     * *Effectiveness_notes*    
     * *Description*    
     Contains a description of this individual mitigation including any strengths and shortcomings of this mitigation for the weakness.     
     <sub>Optional Mitigation_ID attribute for internal team use to uniquely identify mitigations that are repeated across any number of individual weaknesses. Its value matches the following format: MIT-1. </sub>   
* ***Observed examples*** (see *ObservedExampleType* in the schema path)   
Specifies references to a specific observed instance of a weakness in real-world products. Typically this will be a CVE reference.     
Each Observed_Example element represents a single example.     
Elements:    
     * *Reference* (optional)    
     Identifier for the example being cited. For example, if a CVE is being cited, it should be of the standard CVE identifier format, such as CVE-2005-1951 or CVE-1999-0046.    
    * *Description* (required)    
    Product-independent description of the example being cited. The description should present an unambiguous correlation between the example being described and the weakness that it is meant to exemplify.     
    * *Link* (optional)   
    Valid URL where more information regarding this example can be obtained.    

* ***Functional Areas*** (see *FunctionalAreasType* in the schema path)  
Contains one or more functional_area elements, each of which identifies the functional area in which the weakness is most likely to occur. For example, CWE-23: Relative Path Traversal may occur in functional areas of software related to file processing.    
*Functional_Area* element required.     
   <sub>Not in link 2</sub>    
       
* ***Affected Resources*** (see *AffectedResourcesType* in the schema path)   
To identify system resources that can be affected by an exploit of this weakness.     
    
* ***Taxonomy Mappings*** (see *TaxonomyMappingsType* in the schema path)   
To provide a mapping from an entry (Weakness or Category) in CWE to an equivalent entry in a different taxonomy.     
The required *Taxonomy_Name* attribute identifies the taxonomy to which the mapping is being made.     
Elements:    
     * *Entry_ID* and *Entry_Name*    
     To identify the ID and name of the entry which is being mapped.     
     * *Mapping_Fit*    
     Identifies how close the CWE is to the entry in the taxonomy.    
         
* ***Related Attack Patterns*** (see *RelatedAttackPatternsType* in the schema path)   
Contains references to attack patterns associated with this weakness. The association implies those attack patterns may be applicable if an instance of this weakness exists. Each related attack pattern is identified by a CAPEC identifier.

* ***Notes*** (see *NotesType* in the schema path)   
Contains one or more *Note* elements, each of which is used to provide any additional comments about an entry that cannot be captured using other elements.










