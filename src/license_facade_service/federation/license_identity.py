from __future__ import annotations

from uuid import UUID, uuid5

from src.license_facade_service.federation.models import CanonicalLicenseIdentity

LFS_LICENSE_NAMESPACE = UUID("7f2f3f89-c03d-5efc-a6b8-4f9a6956cc31")


def build_canonical_license_identity(
    *,
    authority_node_id: str,
    local_id: str,
    version: str,
) -> CanonicalLicenseIdentity:
    authority = authority_node_id.strip()
    local = local_id.strip()
    immutable_version = version.strip()
    if not authority or not local or not immutable_version:
        raise ValueError("authority_node_id, local_id, and version are required")

    stable_name = f"{authority}|{local}|{immutable_version}"
    resolving_uuid = str(uuid5(LFS_LICENSE_NAMESPACE, stable_name))
    canonical_id = f"lfs:{authority}:{local}:{immutable_version}"
    return CanonicalLicenseIdentity(
        authorityNodeId=authority,
        localId=local,
        version=immutable_version,
        canonicalId=canonical_id,
        resolvingUuid=resolving_uuid,
    )
