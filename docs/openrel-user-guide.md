# How OpenREL works in the License Facade Service

## Overview

OpenREL is available in the License Facade Service (LFS) as a read-only gateway to an external OpenREL provider.

```text
User or application
        |
        | GET /openrel/api/v0.4/...
        v
License Facade Service
        |
        | Controlled HTTPS request
        v
External OpenREL provider
        |
        | Vocabulary data in JSON
        v
LFS validates the response
        |
        v
User receives validated JSON
```

Users call LFS rather than contacting the configured OpenREL provider directly. LFS validates the request, safely retrieves the provider data, validates the response, and returns the result as unwrapped JSON.

## Using OpenREL through LFS

The OpenREL endpoints are available in the LFS Swagger interface at:

```text
https://<your-lfs-host>/docs
```

They appear under the **OpenREL** tag. LFS provides 17 read-only `GET` operations, including:

```http
GET /openrel/api/v0.4/actions
GET /openrel/api/v0.4/actions/{id}
GET /openrel/api/v0.4/constraints
GET /openrel/api/v0.4/mappings
GET /openrel/api/v0.4/ruleclasses
```

Some endpoints accept an optional `prefix` filter:

```http
GET /openrel/api/v0.4/actions?prefix=odrl
```

Example using a local LFS instance:

```bash
curl -sS "http://localhost:12104/openrel/api/v0.4/actions"
curl -sS "http://localhost:12104/openrel/api/v0.4/actions?prefix=odrl"
curl -sS "http://localhost:12104/openrel/api/v0.4/actions/odrl%3Ause"
curl -sS "http://localhost:12104/openrel/api/v0.4/mappings"
```

In the detail example, `%3A` is the percent-encoded form of a colon. Reserved characters in identifiers must be percent-encoded. Transporting complete IRIs in a path can depend on how intervening reverse proxies handle encoded characters and slashes.

## What happens when a request is received

When a user calls an OpenREL endpoint, LFS:

1. Validates the identifier and query parameters.
2. Constructs a request using the configured OpenREL API root and a fixed set of supported routes.
3. Checks the provider destination against its network security policy.
4. Sends a controlled request to the external provider.
5. Applies timeouts, retry limits, redirect protection, and response-size limits.
6. Parses the response as strict JSON and rejects duplicate object keys.
7. Validates the returned OpenREL resource structure.
8. Removes unsupported provider fields.
9. Returns the validated response without adding an LFS wrapper.

LFS does not forward the caller's `Authorization` header, cookies, or arbitrary headers to the provider.

## What OpenREL provides

OpenREL supplies vocabulary and knowledge-base resources that help applications understand rights-related concepts. The available resource groups include:

- actions;
- constraints;
- left operands;
- mappings;
- action classes;
- asset classes;
- constraint classes;
- left-operand classes;
- rule classes.

These resources are external provider data. They are not authoritative licence records owned by LFS.

## Storage and federation

OpenREL is separate from LFS licence storage and LFS federation.

OpenREL responses are:

- not stored in the LFS PostgreSQL database;
- not indexed in the LFS RDF/Fuseki service;
- not published in the LFS federation catalog;
- not added to the LFS federation change feed;
- not synchronized between LFS nodes.

The phrase **OpenREL data is not federated** applies only to OpenREL data. It does not mean that LFS federation is disabled. Normal LFS licence records can still be published and synchronized between trusted LFS nodes.

## Availability and errors

OpenREL is an optional LFS component. Problems with it do not stop normal licence resolution or LFS federation.

Typical behavior includes:

| Situation | OpenREL behavior | Other LFS functionality |
|---|---|---|
| OpenREL is disabled | Returns `503 OpenREL Disabled` | Continues normally |
| Configuration is invalid | Returns `503 OpenREL Configuration Unavailable` | Continues normally |
| Provider is unreachable | Returns an RFC 9457 provider-unavailable problem | Continues normally |
| Provider times out | Returns `504 OpenREL Provider Timeout` | Continues normally |
| Requested detail is absent | Returns `404 OpenREL Resource Not Found` | Continues normally |
| Provider returns invalid data | Returns a `502` validation or protocol problem | Continues normally |

LFS-generated error responses use the `application/problem+json` media type. Provider response bodies, credentials, internal addresses, and tracebacks are not exposed to callers.

## Readiness

The LFS readiness endpoint reports whether OpenREL is enabled and whether its configuration is valid:

```http
GET /api/v1/ready
```

Example when OpenREL is disabled:

```json
{
  "openrel": {
    "enabled": false,
    "ready": null,
    "errors": []
  }
}
```

Example when OpenREL is enabled and its configuration is valid:

```json
{
  "openrel": {
    "enabled": true,
    "ready": true,
    "errors": []
  }
}
```

This is a configuration-readiness check. It does not contact the external OpenREL provider. Provider reachability is evaluated when an OpenREL endpoint is called.

## Summary

LFS gives users one safe and documented API for reading external OpenREL vocabulary data. LFS validates and protects the exchange while keeping OpenREL data separate from licence storage, RDF indexing, and federation.
