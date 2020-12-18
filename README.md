# DataDrivenSecurity

Study of some security data standards

## CWE
![picture](/image/logo_cwe.jpg)

**C**ommon **W**eakness **E**nnumeration is a community-developed list of weaknesses for software and hardware maintained by [MITRE](https://www.mitre.org/).
In this standard each unique weakness is assigned a specific CWE number.       
In order to describe a weakness there is a specific [SCHEMA](https://cwe.mitre.org/documents/schema/).         
So as to study this standard, we can access and download its data from: https://cwe.mitre.org/data/downloads.html. Once we do so, we will be able to see our data structure.         
In the following lines we will have a close look at each one of the simple types of the defined schema and values that are present in our dataset (our downloaded file) to be able to grasp which type of information we will be dealing with.        
        
***AbstractionEnumeration***      
The CWE entries in the list form a tree of different abstraction layers:   
* Pillar      
An example of a a CWE pillar is: CWE-118: Incorrect Access of Indexable Resource ('Range Error').
* Class      
Classes are also very abstract entries. Language and technology independent. An example of a CWE class is: CWE-119: Improper Restriction of Operations whithin the Bounds of a Memory Buffer.
* Base      
Bases are more specific than classes. An example, CWE-787: Out-Of.Bounds-Write and is a child of CWE-119.
* Variant      
The most specific types of weaknesses. An example of such is CWE-121: Stack-based Buffer Overflow which is a child of CWE-787.       



So as to study this standard, we can access and download its data from: https://cwe.mitre.org/data/downloads.html

## Usage

```python
import foobar

foobar.pluralize('word') # returns 'words'
foobar.pluralize('goose') # returns 'geese'
foobar.singularize('phenomena') # returns 'phenomenon'
```

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License
[MIT](https://choosealicense.com/licenses/mit/)
