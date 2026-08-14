# SPDX 3.0.1 JSON Schema provenance

- SPDX version: 3.0.1
- Official source URL: https://spdx.org/schema/3.0.1/spdx-json-schema.json
- Retrieval date: 2026-08-12
- SHA-256: 571dd17d52ad567cb5b44c2fdf0c57f013d08584f00e4f30b4f744dcca0fbb4c
- JSON Schema dialect: Draft 2020-12 (`https://json-schema.org/draft/2020-12/schema`)
- Upstream release reference: official `spdx.org` release endpoint for the SPDX 3.0.1 schema; the GitHub `develop` content differs and is intentionally not used for the pinned artifact.
- SPDX upstream licensing / redistribution note: the SPDX project content is distributed under the SPDX project licensing and attribution rules. This vendored artifact is kept for offline, local structural validation in LFS and is not redistributed as a separate, unrelated schema package.
- Intended use: offline structural validation of generated SPDX 3.0.1 JSON-LD documents in the License Facade Service.
- Semantic validation note: OWL/SHACL semantic validation is not implemented by this project. This vendored schema is used only for structural validation. The generated document must still be reviewed for semantic conformance separately.
- Update procedure: fetch the exact official URL, verify the SHA-256 matches the value above, store the bytes under `vendor/spdx/3.0.1/spdx-json-schema.json`, and update this file before any runtime usage.
- Verification requirement: runtime and tests must load the checked-in local schema. Network access is not allowed during validation.
