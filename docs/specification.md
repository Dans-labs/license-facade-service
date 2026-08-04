# API Specification Note

This note aligns the implementation with `LICENCE FACADE SERVICE - Rights & Ethics.docx.pdf`.

## Normative ambiguity

The introductory prose suggests HTML as the default landing page, but **normative Table 2** defines the base `/licences/{id}` endpoint as the mandatory machine-readable metadata resource.  
This implementation follows the normative table:

- no `Accept` header → `application/json`
- `Accept: */*` → `application/json`
- `Accept: text/html` → HTML
- unsupported media types → `406 application/problem+json`

`/api/v1/licences/{id}` is the specification alias; `/api/v1/licenses/{id}` is the documented implementation path.

## Conformance matrix

| PDF endpoint | Status | Implemented media type | When unavailable | Upstream limitation |
|---|---|---|---|---|
| `/licences/{id}` | Mandatory | negotiated; default JSON | `406` on unsupported `Accept` | none |
| `/licences/{id}/html` | Optional | `text/html` | 404/problem if unavailable | none |
| `/licences/{id}/json-ld` | Optional | `application/ld+json` | 404/problem if unavailable | none |
| `/licences/{id}/original` | Mandatory | redirect to curated `https://...` | 404/problem and conformance failure if missing | SPDX `reference` is **not** treated as original |
| `/licences/{id}/machine` | Mandatory | `application/ld+json`, `text/turtle`, or `application/rdf+xml` depending on curated rep | 404/problem and conformance failure if missing | SPDX metadata alone does **not** satisfy machine |
| `/licences/{id}/legal` | Optional | curated source-defined representation | 404/problem if unavailable | no invented legal code |
| `/licences/{id}/encoding` | Optional | redirect to curated encoding URL | 404/problem if unavailable | no invented encoding URL |

## Table 4 response fields

Detailed JSON metadata includes:

- `uri`
- `referenceNumber`
- `licenseId` / `licenseID` / `licenceID`
- `name`
- `detailsURL` (local `/licenses/{id}/json`)
- `spdxDetailsURL` (upstream SPDX details URL)
- `reference`
- `isDeprecatedLicenseId` / `isDeprecatedLicenseID`
- `seeAlso`
- `isOsiApproved`
- `licenseText`
- `standardLicenseTemplate`
- `licenseTextHtml`
- `crossRef`
- `representations`
- `representationStatus`
- `conformance`
- `_links`

Missing mandatory fields are not fabricated; the record is marked non-conformant instead.

## Table 6 mappings

- `detailsURL` → `/api/v1/licenses/{id}/json`
- `crossRef[type=original]` → `/api/v1/licenses/{id}/original`
- `crossRef[type=machine]` → `/api/v1/licenses/{id}/machine`
- `crossRef[type=legal]` → `/api/v1/licenses/{id}/legal`

Upstream SPDX cross-references are preserved with provenance/source fields.

## REL validation

The implementation validates RELs syntactically and by registered vocabulary/profile IRIs:

- ODRL
- ccREL
- DALICC
- OpenREL
- Dublin Core where allowed
- schema.org for agents/concepts/things

This is **syntax/vocabulary validation only**, not legal or semantic validation.

