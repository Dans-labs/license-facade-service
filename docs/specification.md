# API Specification (Implemented Contract)

## Canonical representation behavior

`GET /api/v1/licenses/{id}` negotiates by `Accept`.
`/api/v1/licences/{id}` is a compatibility alias with identical behavior.

- Missing `Accept` or `*/*` => `text/html`.
- Supported: `text/html`, `application/json`, `application/ld+json`, `text/turtle`, `application/rdf+xml`.
- Unsupported media types => `406 application/problem+json`.
- Responses include `Cache-Control`; negotiated responses include `Vary: Accept`; all include `Content-Location`.

Convenience routes (`/html`, `/json`, `/json-ld`, `/turtle`, `/rdfxml`) reuse the same service-layer render logic as negotiated responses.

## Identifier resolution

- SPDX ID (exact match, case-sensitive)
- LFS UUID (validated with UUID type)
- URL-encoded full LFS URI
- explicit aliases where present

Invalid/non-existent identifiers return one consistent `404 application/problem+json`.

## Representation table

| Endpoint | Purpose | Media type | Status | When unavailable |
|---|---|---|---|---|
| `/api/v1/licenses/{id}` | Canonical negotiated access | negotiated | Mandatory | `406` for unsupported `Accept`; `404` for unknown id |
| `/api/v1/licenses/{id}/html` | Human landing page | `text/html` | Mandatory | `404` for unknown id |
| `/api/v1/licenses/{id}/json` | SPDX-compatible metadata | `application/json` | Mandatory | `404` for unknown id |
| `/api/v1/licenses/{id}/json-ld` | JSON-LD view | `application/ld+json` | Mandatory | `404` for unknown id |
| `/api/v1/licenses/{id}/turtle` | RDF Turtle view | `text/turtle` | Mandatory | `404` for unknown id |
| `/api/v1/licenses/{id}/rdfxml` | RDF/XML view | `application/rdf+xml` | Mandatory | `404` for unknown id |
| `/api/v1/licenses/{id}/original` | Authoritative curated source | redirect to source URL | Optional per license | `404` with links to available representations |
| `/api/v1/licenses/{id}/legal` | Curated legal representation | source-defined | Optional per license | `404` with links to available representations |
| `/api/v1/licenses/{id}/machine` | Rights-expression representation | source-defined (REL profile/vocabulary) | Mandatory capability, optional per license | `404` with links to available representations |
| `/api/v1/licenses/{id}/encoding` | Rights encoding by reference | redirect to encoding URL | Optional per license | `404` with links to available representations |

## Table 4 metadata fields

Canonical JSON metadata includes the Table 4 fields and aliases:

- `uri`
- `referenceNumber`
- `licenseId` / `licenseID` / `licenceID`
- `name`
- `detailsURL` / `detailsUrl`
- `reference`
- `isDeprecatedLicenseId` / `isDeprecatedLicenseID`
- `seeAlso`
- `isOsiApproved`
- `licenseText`
- `standardLicenseTemplate`
- `licenseTextHtml`
- `crossRef` with `URL`, `timeStamp`, `match`, `isValid`, `isLive`, `isWayBackLink`, `order`
- `representations` and `_links`

## Rights & Ethics discrepancy note

Normative requirements require `/machine` capability while current SPDX metadata does not guarantee rights-expression content per license. Implemented behavior follows the normative requirement without inventing provisions:

- endpoint exists and is mandatory as a capability;
- returns `404` problem details when a license lacks curated REL-compliant machine representation.
