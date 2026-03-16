# Licence Facade Service (LFS)

Wim Hugo, DANS

# **Abstract**

The specification covers the design and operation of a **Licence Facade Service** (LFS), enabling end users and developers to unambiguously identify and reference licences for datasets, and optionally obtain human- and machine- readable representations of the licence provisions where available.

# **Status of This Document**

Draft for discussion. Open for review by EDEN technical working groups.

# **Introduction**

One of the major objectives of Open Science, and of the FAIR principles (R1.1), require the provision of a clear and unambiguous licence that governs the reuse of a dataset. There are three interrelated problems in this regard:

1. There is a large number of custom licences attached to datasets in practice, and these licences have widely differing implementation styles \- from representation in publicly available text documents to machine-readable formats such as JSON-LD, and they typically have widely different ways in which they are referenced.  
2. Even for widely adopted and machine-actionable licences, such as the Creative Commons licences, there are no standardised practices on how to identify and refer to these licences, leading to a very wide range of text-based, URI-based, or URL-based identifiers for these licences.   
3. For reliably identifiable licences, it is not guaranteed that the provisions of the licence will be machine-readable or actionable, or that human-readable or legal representations of the licence are available.

There are existing services for providing references and metadata for commonly used licences, specifically the SPDX service maintained by the Linux Foundation. This service is in widespread use and should be supplemented by the LFS, instead of aiming to replace it. The SPDX service has some deficiencies that the LFS aims to address:

1. **Licence Inventory Scope**: New licences and their metadata are added to SPDX as pull requests, and such pull requests need not be accepted by the SPDX. This creates a problem if a licence is of use to a section of the research data management community.  
2. **Metadata Scope**: The licence metadata in SPDX is limited, focused on the needs of the open source (software) code ecosystem. Licence metadata elements that are in scope for the research data community will not be present, and are unlikely to be added in future.  
3. **Licence representations**: Licence metadata are represented by SPDX as a human-readable HTML page, or as a JSON equivalent. The human-readable metadata contains some references to alternatives in the web (often also human-readable representations of the same licence). The main objectives for representations of a licence should be authoritative versions of the following:  
   1. Human-readable metadata (HTML, text, …) \- default target of identifier resolution;  
   2. Human readable licence provisions (indirectly provided by hyperlinks in SPDX to original licence web pages, with no underlying tag or schema structure to reliably obtain this representation).  
   3. Machine-readable representation of the licence provisions. Clauses or rules within the licence are currently not provided by SPDX (i.e. Machine-readable Permissions, Prohibitions and Duties).  
   4. Legal code for the licence provisions (not currently provided by SPDX, sometimes obtainable via the original metadata page).

# **Scope**

## **In scope**

The specification in this document addresses the first two of these concerns by proposing a facade for licence identification and disambiguation, based on existing services and infrastructures. A facade service offers a simplified and unified interface that may combine multiple backend services.

## **Out of scope**

Successful operation of the LFS depends on **curation** and **content management** that are not addressed in the technical specification.

# **Conformance**

The keywords MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are to be interpreted as described in RFC 2119 (https://www.rfc-editor.org/rfc/rfc2119).

# **Normative Requirements**

## **Requirement Group 1 – Persistent Identification Behaviour**

* {{ LFS-REQ-1-01 }} The Licence Facade Service (LFS) SHOULD emulate the behavior and expectations associated with persistent identifiers in respect of uniqueness, persistence, and resolvability. 

## **Requirement Group 2 – LFS Call and Response Options**

* {{ LFS-REQ-2-01  }} The LFS MUST provide a REST API interface for requests to the SPDX service. (The SPDX Service does not currently provide such a service, but addresses aspects of it indirectly).  
* {{ LFS-REQ-2-02  }} The LFS MUST adhere to the response definition of the SPDX service. The LFS MAY extend this request and response definition provided it remains compatible with the SPDX definition.  
* {{ LFS-REQ-2-03  }} The LFS service MUST provide the call methods listed in Table 1\.  
* {{ LFS-REQ-2-04  }} The LFS service MUST provide the representation options Listed in Table 2 as ‘Mandatory’ in its call response, in addition to the standard SPDX response metadata. It MAY provide the ‘Optional’ representation options.

*Table 1: LFS Call Summary*

| Call | Description | Response |
| :---- | :---- | :---- |
| /licences | A list of all licences that LFS has a record for. SPDX Equivalents [Human readable](https://spdx.org/licenses/) [Machine-readable](https://raw.githubusercontent.com/spdx/license-list-data/main/json/licenses.json) | Table 4 |
| /licences/{id} | The licence metadata that is applicable to the licence itself. | Table 4 |

*Table 2: Representation and Resolution Options*

| Option | Description | Cardinality |
| :---- | :---- | :---- |
| /licences/{id} | MachineHuman-readable metadata landing page for the licence. If SPDX exists, this is the default. | Mandatory |
| /licences/{id}/html | Human-readable metadata landing page for the licence. If SPDX exists, this is the default. | Optional |
| /licences/{id}/json-ld | Machine-readable licence metadata in JSON-LD | Optional |
| /licences/{id}/original | The human-readable landing page for the licence at its curating organisation | Mandatory |
| /licences/{id}/machine | The machine-readable representation of the licence, based on standardised Rights Encoding Languages Listed in Table 3\. | Optional |
| /licences/{id}/legal | A legally valid representation of the provisions of the licence, which may be applicable in a specific jurisdiction only. | Optional |

## **Requirement Group 3 – Rights Encoding Languages**

* {{ LFS-REQ-3-01  }} The LFS MUST use one of the permissible Rights Encoding Languages (RELs) listed in Table 3\. Licence provision encodings MUST employ one or more of the listed RELs to define the machine-readable version of the licence.  
* {{ LFS-REQ-3-02  }} The EOSC REL Vocabulary, in preparation by the EOSC Beyond project, MUST replace the licence encoding vocabulary once it is available.   
* {{ LFS-REQ-3-03  }} The replacement MUST be in full for new licences, or MUST be via a mapping or profile for previously encoded licences.   
* {{ LFS-REQ-3-04  }} In cases where a mapping  or profile is implemented, the original profile MUST remain available. 

*Table 3: Permissible Rights Encoding Languages*

| Rights Encoding Language | Description | Reference |
| :---- | :---- | :---- |
| [ODRL](https://www.w3.org/TR/odrl-model/) | The Open Digital Rights Language is the preferred and default REL, and licence provisions that match the ODRL MUST be encoded using this vocabulary.  |  |
| [ccREL](https://opensource.creativecommons.org/ccrel/) | ccREL MUST be used as a second priority to encode provisions that are not accommodated by ODRL. |  |
| [DALICC](https://dalicc.github.io/)[^1] | The DALICC vocabulary or its equivalent MAY be used for provisions that are not covered by ODRL and ccREL. |  |
| [Dublin Core](https://dublincore.org/) | Dublin Core MAY be used for such provisions as not covered by ODRL and ccREL. |  |
| schema.org | The [schema.org](http://schema.org) vocabulary MUST be used to describe agents (actors), concepts, and things that are referenced by or have actions assigned in the licence provisions.  |  |
| EOSC vocabulary | Once this vocabulary becomes available, it will become the preferred REL for licence encoding in EOSC. |  |

## **Requirement Group 4 – Metadata and Response Definitions**

* {{ LFS-REQ-4-01 }} The LFS MUST return metadata in its responses that match the metadata definition in Table 4\.  
* {{ LFS-REQ-4-02  }} The LFS MUST return mappings of licence metadata, obtained from the SPDX registry, for standard representations of licence id details, as defined in Table 6\.

*Table 4: Licence Metadata Elements*

| Element (Proposal) | Description | SPDX | Cardinality |  |
| :---- | :---- | :---- | :---- | :---- |
|  |  |  | /licence | /licence/{id} |
| (uri) | The unique URI provided for the licence by LFS \- emulates a PID for licences | No | 1 | 1 |
| referenceNumber | The UUID for the licence in SPDX registry | Yes | 1 |  |
| licenceID | The licence identifier in the SPDX context | Yes | 1 |  |
| name | The name or title of the licence | Yes | 1 | 1 |
| detailsURL | The URL to a JSON representation of the licence metadata at SPDX | Yes | 1 |  |
| reference | The URL to an HTMLrepresentation of the licence metadata at SPDX | Yes | 1 |  |
| isDeprecatedLicenseID | The Licence referenced by the ID has been deprecated | Yes | 1 | 1 |
| seeAlso | Other representations of the same licence. May, in some cases, contain a reference to legal code. | Yes | 0..n | 0..n |
| isOsiApproved | The licence is listed and approved by the OSI | Yes | 1 |  |
| licenseText | The text of the licence in human readable format | Yes |  | 1 |
| standardLicenseTemplate | A template for modification of the licence | Yes |  | 1 |
| licenseTextHtml | An HTML representation of the human readable format | Yes |  | 1 |
| crossRef | Additional cross-references for the licence. Details in Table 5\. May, in some cases, contain a reference to legal code. See proposed extensions in Table 6\. | Yes |  | 0..n |

*Table 5: Licence Metadata Element Detail: crossRef*

| Element (Proposal) | Description | SPDX | Cardinality |  |
| :---- | :---- | :---- | :---- | :---- |
|  |  |  | /licence | /licence/{id} |
| match | This flag is true if the cross reference is an example of the licence that matches the template | Yes |  | 1 |
| URL | The URL to the cross-reference | Yes |  | 1 |
| isValid | Whether the cross-reference is still valid | Yes |  | 1 |
| isLive | Whether the cross-reference is still resolvable | Yes |  | 1 |
| timeStamp | Date of last access | Yes |  | 1 |
| isWayBackLink | If not resolvable, is the link resolvable via the WayBackMachine? | Yes |  | 1 |
| order | The order in which the cross-references must be displayed | Yes |  | 1 |
|  |  |  |  |  |

*Table 6: Licence Metadata Mappings for crossRef Extension*

| Source Element | Target Element Type | Cardinality |  |
| :---- | :---- | :---- | :---- |
|  |  | /licence | /licence/{id} |
| detailsURL | /licences/{id}/json | 1 | 1 |
| crossRef.URL type=’original’ | /licences/{id}/original |  | 0..1 |
| crossRef.URL type=’machine’ | /licences/{id}/machine |  | 0..1 |
| crossRef.URL type=’legal’ | /licences/{id}/legal |  | 0..1 |

# 

# **Non-normative Guidance**

The following projects, under way in the EU, will influence this specification:

1. EOSC Beyond: EOSC Beyond is tasked explicitly with definition of a REL vocabulary for use in EOSC, with a landscape review of design considerations to be published in September 2025, and a vocabulary in September 2026\.  
2. EOSC EDEN and FIDELIS: These projects are reviewing the framework and definition of the actors (agents), concepts, and things in scope for data repositories and their associated services, and this could lead to a more authoritative and inclusive conceptual model to use for identification and description of the actions associated with licence provisions. Likely availability \- September 2025\.

# **References**

1. EOSC Interoperability Framework   
2. [https://opensource.org/licenses](https://opensource.org/licenses)  
3. [https://spdx.org/licenses/](https://spdx.org/licenses/)   
4. [https://dalicc.github.io/](https://dalicc.github.io/)   
5. SPDX inclusion principles \- [https://github.com/spdx/license-list-XML/blob/main/DOCS/license-inclusion-principles.md](https://github.com/spdx/license-list-XML/blob/main/DOCS/license-inclusion-principles.md) 

[^1]:  The DALICC project defined a list of vocabulary items often encountered in licence provisions, but for which equivalents do not exist in other RELs. These vocabulary items remain useful and applicable even though the vocabulary items are now not resolvable.
