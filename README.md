# License Facade Service

FastAPI service for SPDX-compatible licence metadata, curated negotiated representations, custom-licence registration, optional OpenREL policy evaluation, federated revision publication, and asynchronous RDF indexing.

Current integrated application version: **0.3.5**.

## Run

```bash
uv sync
uv run python -m src.license_facade_service.main
```

## Feature summary

- public licence metadata and representation routes with RFC 9457 problem responses
- custom-licence registration for `local`, `federated`, and `spdx-submission` scopes
- optional read-only OpenREL provider facade and policy evaluation workflow
- persisted OpenREL plans, admin review, apply, and rollback
- append-only federated revision publication with latest-event projection
- asynchronous RDF outbox processing with PostgreSQL as source of truth while Fuseki is unavailable

## Documentation

- Rights & Ethics compliance matrix: `docs/lfs-rights-ethics-compliance.md`
- Technical specification: `docs/specification.md`
- Production deployment guide: `docs/production-docker-deployment.md`
- Custom licence and OpenREL operational guide: `docs/custom-licence-registration-guide.md`
- OpenREL operator checklist: `docs/openrel-operator-verification.md`

## OpenAPI and Swagger

- Swagger UI: `/docs`
- ReDoc: `/redoc`
- Raw schema: `/openapi.json`

Documented OpenREL admin endpoints:

- `POST /api/v1/admin/openrel/evaluations`
- `GET /api/v1/admin/openrel/policy-states`
- `GET /api/v1/admin/openrel/policy-states/{state_id}`
- `GET /api/v1/admin/openrel/policy-states/{state_id}/events`
- `POST /api/v1/admin/openrel/policy-states/{state_id}/approve`
- `POST /api/v1/admin/openrel/policy-states/{state_id}/reject`
- `POST /api/v1/admin/openrel/policy-states/{state_id}/apply`
- `POST /api/v1/admin/openrel/policy-states/{state_id}/rollback`

## Deployment profiles

- `app`: API with optional external PostgreSQL/Fuseki/OpenREL configuration
- `production`: PostgreSQL + Alembic migration owner + API + federation worker + custom publication worker + RDF worker
- `federation-demo`: two isolated nodes for trust, synchronization, OpenREL, and federated revision demonstrations
