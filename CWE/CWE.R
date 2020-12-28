### NESTED CWE DATAFRAME ###

#From csv we create our dataframe
cwe <- read.csv("cwe.csv", FALSE)
colnames(cwe)=cwe[c(1),]
cwe=cwe[-c(1),]
View(cwe)
#We create a matrix for Related.Weaknesses
#matrix columns: Nature , CWE_ID, VIEW_ID
#Note that we omit Ordinal (it is always Primary)
library(stringr)
i=0
for (b in cwe$`Related Weaknesses`)
{
i=i+1
nature <- c(unlist(str_extract_all(b, "(?<=NATURE:)\\w+")))
cwe_id<- c(unlist(str_extract_all(b, "(?<=CWE ID:)\\w+")))
view_id <- c(unlist(str_extract_all(b, "(?<=VIEW ID:)\\w+")))
mtrx <- cbind(nature, cwe_id, view_id)
cwe$`Related Weaknesses`[i] <- list(mtrx)
}
#We create a vector for Weakness.Ordinalities
#Note that we omit Description
i=0
for (b in cwe$`Weakness Ordinalities`){
 i=i+1
 ordinality <- c(unlist(str_extract_all(b, "(?<=ORDINALITY:)\\w+")))
  if(length(ordinality)==0){
   next
  }
  else{
   cwe$`Weakness Ordinalities`[i] <- list(ordinality)
  }
}
#We create a vector for Applicable.Platforms
#Parameter Name is considered same as Class to resolve conflicts
i=0
for (b in cwe$`Applicable Platforms`){
 i=i+1
 b <- gsub('-', '_', b)
 b <- gsub('NAME', 'CLASS', b)
 platforms <- c(unlist(str_extract_all(b, "(?<=CLASS:)\\w+")))
 prevalence <- c(unlist(str_extract_all(b, "(?<=PREVALENCE:)\\w+")))
  if(length(platforms)==0){
   next
   }
 mtrx <- cbind(platforms, prevalence)
 cwe$`Applicable Platforms`[i] <- list(mtrx)
}
#We create a proper str for Background.Details
i=0
for (b in cwe$`Background Details`){
 i=i+1
 det <- c(unlist(str_extract_all(b, "[^::]+")))
  if(length(det)==0){
   next
  }
 cwe$`Background Details`[i] <- list(det)
}
#Creating a vector for Alternate.Terms
#Note that we omit the Description of the alternate terms
i=0
for (b in cwe$`Alternate Terms`){
 i=i+1
 terms <- c(unlist(str_extract_all(b, "(?<=TERM:)\\w+( +\\w+)*")))
 if(length(terms)==0){
  next
 }
 cwe$`Alternate Terms`[i] <- list(terms)
}
#We create a matrix for Modes.Of.Introduction
#matrix rows: phase(1) and notes(2)
i=0
for (b in cwe$`Modes Of Introduction`){
 i=i+1
 if(b==""){
  next
 }
 b <- gsub('::','|', b)
 phase <- c(unlist(str_extract(b, "[^(||)]+")))
 ph <- c()
 note <- c()
 while(!is.na(phase)){
   b <- str_replace(b,"[^(||)]+",'|')
   ph <- c(unlist(append(ph, c(unlist(str_extract(phase, "(?<=PHASE:)\\w+( +\\w+)*"))), after=length(ph))))
   note <- c(unlist(append(note, c(unlist(str_extract(phase, "(?<=NOTE:REALIZATION:)|(?<=NOTE:)\\w+( +\\w+)*"))), after=length(note))))
    if(is.na(tail(note, n=1))){
      note <- append(note, c("-"))
      note <- c(unlist(max(note, na.rm = TRUE)))
     }
   phase <- c(unlist(str_extract(b, "[^(||)]+")))
  }
 mtrx <- t(cbind(ph, note))
 cwe$`Modes Of Introduction`[i]<- list(mtrx)
}
#We create a matrix for Common.Consequences
#matrix rows: scope(1) and impact(2)
#Likelihood is not considered due to its small num of appearances
#Notes is omitted too
i=0
for (b in cwe$`Common Consequences`){
 i=i+1
 if(b==""){
  next
 }
 b <- gsub('::','|', b)
 b <- gsub("[()]", "", b)
 cc <- c(unlist(str_extract(b, "[^(||)]+")))
 scope <- c()
 impact <- c()
 while(!is.na(cc)){
  b <- str_replace(b,"[^(||)]+",'|')
  scope <- c(unlist(append(scope, c(paste(unlist(str_extract_all(cc, "(?<=SCOPE:)\\w+( +\\w+)*")), collapse="/")), after=length(scope))))
  impact <- c(unlist(append(impact, c(paste(unlist(str_extract_all(cc, "(?<=IMPACT:)\\w+( +\\w+)*|(?<=IMPACT:)\\w+(:+ +\\w+)*")), collapse="/")), after=length(impact))))
  if(is.na(tail(impact, n=1))){
   impact <- append(impact, c("-"))
   impact <- c(unlist(max(impact, na.rm = TRUE)))
  }
  cc <- c(unlist(str_extract(b, "[^(||)]+")))
 }
 mtrx <- t(cbind(scope, impact))
 cwe$`Common Consequences`[i]<- list(mtrx)
}
#We create a matrix for Detection.Methods
#matrix columns: Method(1) Description(2) Effectiveness (3)
#Effectiveness Description is not considered
i=0
for (b in cwe$`Detection Methods`){
  i=i+1
  if(b==""){
    next
  }
  b <- gsub('::','|', b)
  b <- gsub("[()]", "", b)
  dmethod <- c(unlist(str_extract(b, "[^(||)]+")))
  method <- c()
  descr <- c()
  eff <- c()
  while(!is.na(dmethod)){
    b <- str_replace(b,"[^(||)]+",'|')
    method <- c(unlist(append(method, c(unlist(str_extract(dmethod, "(?<=METHOD:)\\w+( +\\w+)*"))), after=length(method))))
    descr <- c(unlist(append(descr, c(unlist(str_extract(dmethod, "(?<=DESCRIPTION:)\\w+( +\\w+)*"))), after=length(descr))))
    eff <- c(unlist(append(eff, c(unlist(str_extract(dmethod, "(?<=EFFECTIVENESS:)\\w+( +\\w+)*"))), after=length(eff))))
    if(is.na(tail(eff, n=1))){
      eff <- append(eff, c("-"))
      eff <- c(unlist(max(eff, na.rm = TRUE)))
    }
    dmethod <- c(unlist(str_extract(b, "[^(||)]+")))
  }
  mtrx <- cbind(method, descr, eff)
  cwe$`Detection Methods`[i]<- list(mtrx)
}
######Needs to be rethought#########
#We create a matrix for Potential.Mitigations
#matrix columns: Phase(1) Strategy(2) Description(3) and Effectiveness(4)
#Effectiveness Description is not considered
i=0
for (b in cwe$`Potential Mitigations`){
  i=i+1
  if(b==""){
    next
  }
  b <- gsub('::','|', b)
  b <- gsub("[()]", "", b)
  potential <- c(unlist(str_extract(b, "[^(||)]+")))
  phase <- c()
  strat <- c()
  descr <- c()
  eff <- c()
  while(!is.na(potential)){
    b <- str_replace(b,"[^(||)]+",'|')
    phase <- c(unlist(append(phase, c(unlist(str_extract(potential, "(?<=PHASE:)\\w+( +\\w+)*"))), after=length(phase))))
    strat <- c(unlist(append(strat, c(unlist(str_extract(potential, "(?<=STRATEGY:)\\w+( +\\w+)*"))), after=length(strat))))
    descr <- c(unlist(append(descr, c(unlist(str_extract(potential, "(?<=DESCRIPTION:)\\w+(.+)*+( +\\w+)*"))), after=length(descr))))
    eff <- c(unlist(append(eff, c(unlist(str_extract(dmethod, "(?<=EFFECTIVENESS:)\\w+( +\\w+)*"))), after=length(eff))))
    if(is.na(tail(strat, n=1))){
      strat <- append(strat, c("-"))
      strat <- c(unlist(max(strat, na.rm = TRUE)))
    }
    if(is.na(tail(eff, n=1))){
      eff <- append(eff, c("-"))
      eff <- c(unlist(max(eff, na.rm = TRUE)))
    }
    potential <- c(unlist(str_extract(b, "[^(||)]+")))
  }
  mtrx <- cbind(phase, strat, descr, eff)
  cwe$`Potential Mitigations`[i]<- list(mtrx)
}
######Needs to be rethought#########
#We create a matrix for Observed.Examples
#matrix rows: Reference(1) Description(2) Link(3)
i=0
for (b in cwe$`Observed Examples`){
  i=i+1
  if(b==""){
    next
  }
  b <- gsub('::','|', b)
  b <- gsub("[()]", "", b)
  oex <- c(unlist(str_extract(b, "[^(||)]+")))
  ref <- c()
  descr <- c()
  link <- c()
  while(!is.na(oex)){
    b <- str_replace(b,"[^(||)]+",'|')
    ref <- c(unlist(append(ref, c(unlist(str_extract(oex, "(?<=METHOD:)\\w+( +\\w+)*"))), after=length(method))))
    descr <- c(unlist(append(descr, c(unlist(str_extract(oex, "(?<=DESCRIPTION:)\\w+( +\\w+)*"))), after=length(descr))))
    link <- c(unlist(append(link, c(unlist(str_extract(oex, "(?<=LINK:)\\w+( +\\w+)*"))), after=length(eff))))
    if(is.na(tail(ref, n=1))){
      ref <- append(ref, c("-"))
      ref <- c(unlist(max(ref, na.rm = TRUE)))
    }
    if(is.na(tail(link, n=1))){
      link <- append(link, c("-"))
      link <- c(unlist(max(link, na.rm = TRUE)))
    }
    oex <- c(unlist(str_extract(b, "[^(||)]+")))
  }
  mtrx <- t(cbind(ref, descr, link))
  cwe$`Observed Examples`[i]<- list(mtrx)
}
#We create a proper str for Functional.Areas
i=0
for (b in cwe$`Functional Areas`){
  i=i+1
  det <- c(unlist(str_extract_all(b, "[^::]+")))
  if(length(det)==0){
    next
  }
  cwe$`Functional Areas`[i] <- list(det)
}
#We create a proper str for Afected.Resources
i=0
for (b in cwe$`Affected Resources`){
  i=i+1
  det <- c(unlist(str_extract_all(b, "[^::]+")))
  if(length(det)==0){
    next
  }
  cwe$`Affected Resources`[i] <- list(det)
}
#We create a matrix for Taxonomy.Mapping
#matrix columns: TaxonomyName(1) Entry_Name(2) Entry_ID(3)
#Mapping_Fit is not considered due to its small num of appearances (to be studied)
i=0
for (b in cwe$`Taxonomy Mappings`){
  i=i+1
  if(b==""){
    next
  }
  b <- gsub('::','|', b)
  b <- gsub("[()]", "", b)
  tm <- c(unlist(str_extract(b, "[^(||)]+")))
  tn <- c()
  en <- c()
  eid <- c()
  while(!is.na(tm)){
    b <- str_replace(b,"[^(||)]+",'|')
    tn <- c(unlist(append(tn, c(unlist(str_extract(tm, "(?<=TAXONOMY NAME:)\\w+( +\\w+)*"))), after=length(tn))))
    en <- c(unlist(append(en, c(unlist(str_extract(tm, "(?<=ENTRY NAME:)\\w+( +\\w+)*"))), after=length(en))))
    eid <- c(unlist(append(eid, c(unlist(str_extract(tm, "(?<=ENTRY ID:)\\w+( +\\w+)*"))), after=length(eid))))
    if(is.na(tail(en, n=1))){
      en <- append(en, c("-"))
      en <- c(unlist(max(en, na.rm = TRUE)))
    }
    if(is.na(tail(eid, n=1))){
      eid <- append(eid, c("-"))
      eid <- c(unlist(max(eid, na.rm = TRUE)))
    }
    tm <- c(unlist(str_extract(b, "[^(||)]+")))
  }
  mtrx <- t(cbind(tn, en, eid))
  cwe$`Taxonomy Mappings`[i]<- list(mtrx)
}
#We create a proper str for Related.Attack.Patterns
i=0
for (b in cwe$`Related Attack Patterns`){
  i=i+1
  det <- c(unlist(str_extract_all(b, "[^::]+")))
  if(length(det)==0){
    next
  }
  cwe$`Related Attack Patterns`[i] <- list(det)
}
#We create a matrix for Notes
#matrix rows: Type(1) and Note(2)
i=0
for (b in cwe$Notes){
  i=i+1
  if(b==""){
    next
  }
  b <- gsub('::','|', b)
  b <- gsub("[()]", "", b)
  n <- c(unlist(str_extract(b, "[^(||)]+")))
  type <- c()
  note <- c()
  while(!is.na(n)){
    b <- str_replace(b,"[^(||)]+",'|')
    type <- c(unlist(append(type, c(unlist(str_extract(n, "(?<=TYPE:)\\w+( +\\w+)*"))), after=length(type))))
    note <- c(unlist(append(note, c(unlist(str_extract(n, "(?<=NOTE:)\\w+( +\\w+)*"))), after=length(note))))
    n <- c(unlist(str_extract(b, "[^(||)]+")))
  }
  mtrx <- t(cbind(type, note))
  cwe$Notes[i]<- list(mtrx)
}
