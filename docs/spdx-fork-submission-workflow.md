# SPDX Fork Submission Workflow for LFS

## Purpose

The License Facade Service (LFS) can register a custom licence with the scope:

```json
{
  "scope": "spdx-submission"
}
```

This scope means that the licence is retained locally and prepared for possible contribution to the SPDX License List. It does **not** mean that SPDX has received, reviewed, or accepted the licence.

LFS should not directly create a pull request in the official SPDX repository. Instead, it should create a branch and commit in a controlled fork. An operator can review that commit and manually open an upstream pull request.

## Correct SPDX repository

New SPDX License List contributions belong in:

- Source repository: <https://github.com/spdx/license-list-XML>

Do not submit generated licence changes directly to:

- Generated data repository: <https://github.com/spdx/license-list-data>

`license-list-data` contains generated representations. Its authoritative source is `license-list-XML`.

The XML format in `license-list-XML` is maintained for the SPDX Legal Team and can change. LFS must therefore generate and validate contribution files against a pinned upstream revision.

## Recommended architecture

```text
User registers a custom licence in LFS
                  |
                  v
scope = spdx-submission
status = ready_for_review
                  |
                  v
Human or administrator reviews the licence
                  |
                  v
LFS prepares an SPDX contribution package
                  |
                  v
LFS validates the package against a pinned
spdx/license-list-XML revision
                  |
                  v
LFS creates a branch and commit in the
organization-controlled SPDX fork
                  |
                  v
Human reviews the generated files and diff
                  |
                  v
Human manually creates an upstream pull request
                  |
                  v
SPDX Legal Team reviews the contribution
```

## Repository arrangement

An organization-controlled fork should be used, for example:

```text
Official upstream:
https://github.com/spdx/license-list-XML

Controlled fork:
https://github.com/<organization>/license-list-XML
```

LFS receives write access only to the controlled fork. It should not receive permission to write to the official SPDX repository.

Each submission should use a separate branch, for example:

```text
lfs/licence/DANS-Custom-1.0/<submission-id>
```

LFS must not commit directly to the fork's default branch.

## Recommended workflow states

| Status | Meaning |
|---|---|
| `ready_for_review` | Registered locally and awaiting internal review. |
| `approved_for_preparation` | An authorized operator approved package generation. |
| `preparing` | LFS is generating and validating contribution files. |
| `committed_to_fork` | A branch and commit were created successfully in the controlled fork. |
| `preparation_failed` | Package generation, validation, branch creation, or commit creation failed. |
| `upstream_pr_opened` | An operator manually opened an upstream pull request. |
| `changes_requested` | SPDX reviewers requested changes. |
| `accepted_upstream` | SPDX accepted and merged the contribution. |
| `rejected_upstream` | SPDX declined or closed the contribution without merging it. |

Initially, the upstream pull-request statuses should be updated manually by an authorized operator.

LFS must never mark a licence as `accepted_upstream` merely because it generated files or created a commit in the fork.

## Recommended implementation phases

### Phase 4A — Offline contribution package

Phase 4A should not require GitHub credentials or perform GitHub writes.

It should:

1. Load the immutable custom-licence record from PostgreSQL.
2. Generate the files expected by a pinned revision of `license-list-XML`.
3. Preserve the exact authoritative legal text.
4. Generate a manifest containing file digests and source identifiers.
5. Run the SPDX repository's applicable validation tools.
6. Store validation results and a sanitized audit event.
7. Allow an authorized operator to download and inspect the package.

This phase establishes that LFS can produce a valid, reviewable contribution before it receives repository credentials.

### Phase 4B — Commit to the controlled fork

Phase 4B adds narrowly scoped GitHub access.

It should:

1. Confirm that an administrator approved the package.
2. Fetch the configured fork and pinned upstream base revision.
3. Create a dedicated submission branch.
4. Apply the previously generated and validated contribution package.
5. Rerun validation before committing.
6. Create one deterministic, auditable commit.
7. Push only the dedicated branch to the controlled fork.
8. Record the repository, branch, commit SHA, package digest, source custom-licence UUID, and timestamp.
9. Mark the workflow `committed_to_fork`.

Phase 4B must not automatically open an upstream pull request. The operator reviews the branch and manually creates the pull request from the fork to `spdx/license-list-XML`.

## Security requirements

Use a GitHub App or fine-grained token with access only to the controlled fork.

The credential should have only the permissions required to:

- read repository contents;
- create branches;
- create commits;
- push submission branches.

The implementation must:

- never store GitHub credentials in licence records, audit events, API responses, or logs;
- never include credentials in a persisted Git remote URL;
- never log authorization headers;
- never expose credentials through Swagger examples;
- avoid giving LFS access to unrelated repositories;
- isolate repository operations in a separate worker process;
- validate branch names and prevent arbitrary Git references;
- prohibit force pushes;
- prohibit writes to the default branch;
- record sanitized failure classes rather than raw command output containing secrets.

## Idempotency and retry rules

Branch and commit creation must be idempotent.

A stable submission identity should be derived from values such as:

- source custom-licence UUID;
- custom-licence canonical ID;
- licence version;
- contribution-package digest;
- pinned SPDX upstream base commit.

Retrying the same approved package must not create multiple unrelated branches or commits.

If the package changes after reviewer feedback, LFS should create a new package version and either:

- add a new commit to the existing submission branch; or
- create a new explicitly linked submission branch.

The chosen policy must be documented and audited.

## Data to retain in LFS

LFS should retain:

- custom-licence UUID and canonical ID;
- requested licence ID and version;
- exact legal-text digest;
- generated contribution-package digest;
- SPDX fork owner and repository name;
- submission branch name;
- pinned upstream base commit SHA;
- generated commit SHA;
- workflow status;
- validation result summary;
- timestamps and retry count;
- sanitized failure class;
- append-only audit events for approval, preparation, commit, and manual status changes.

LFS should not retain:

- GitHub access tokens;
- GitHub App private keys in database records;
- credentials embedded in Git URLs;
- uncontrolled Git command output;
- claims that SPDX accepted a contribution before upstream confirmation.

## Manual upstream pull request

After LFS reports `committed_to_fork`, an operator should:

1. Open the branch in the controlled fork.
2. Review every generated file and the complete diff.
3. Confirm validation passed against the expected upstream revision.
4. Confirm the licence identifier, full name, exact text, metadata, and test material are correct.
5. Rebase or regenerate the package if the upstream repository changed materially.
6. Manually open the pull request to `spdx/license-list-XML`.
7. Record the pull-request URL and number in LFS.
8. Update the workflow status as the SPDX review progresses.

## Important distinction

These are separate events:

```text
Registered in LFS
        !=
Prepared for SPDX contribution
        !=
Committed to an SPDX fork
        !=
Submitted as an upstream pull request
        !=
Accepted into the SPDX License List
```

The LFS API and Swagger documentation must make this distinction explicit.

## Recommended next step

Implement Phase 4A first: generate and validate a downloadable contribution package without GitHub access.

Only after the generated files and validation workflow have been reviewed should Phase 4B add permission to create branches and commits in the controlled SPDX fork.
