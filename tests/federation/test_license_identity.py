from __future__ import annotations

import pytest

from src.license_facade_service.federation.license_identity import (
    LFS_LICENSE_NAMESPACE,
    build_canonical_license_identity,
)


def test_canonical_license_identity_uses_fixed_namespace():
    identity = build_canonical_license_identity(
        authority_node_id="de305d54-75b4-431b-adb2-eb6b9e546014",
        local_id="Apache-2.0",
        version="1",
    )
    assert str(LFS_LICENSE_NAMESPACE) == "7f2f3f89-c03d-5efc-a6b8-4f9a6956cc31"
    assert identity.canonicalId == "lfs:de305d54-75b4-431b-adb2-eb6b9e546014:Apache-2.0:1"
    assert identity.resolvingUuid == "3487c1a9-7567-586c-ae1b-ca4ee92d82ef"


def test_canonical_license_identity_fixed_vectors_change_per_identity_component():
    version2 = build_canonical_license_identity(
        authority_node_id="de305d54-75b4-431b-adb2-eb6b9e546014",
        local_id="Apache-2.0",
        version="2",
    )
    other_authority = build_canonical_license_identity(
        authority_node_id="11111111-1111-1111-1111-111111111111",
        local_id="Apache-2.0",
        version="1",
    )
    other_local_id = build_canonical_license_identity(
        authority_node_id="de305d54-75b4-431b-adb2-eb6b9e546014",
        local_id="MIT",
        version="1",
    )

    assert version2.resolvingUuid == "0eddd208-05fc-50ce-a509-1485f648578d"
    assert other_authority.resolvingUuid == "c8a13076-79ea-5fb2-900c-78cb6267c6a3"
    assert other_local_id.resolvingUuid == "2b891810-2af9-5244-b068-ad920d561cc2"


@pytest.mark.parametrize("local_id", ["", "   "])
def test_canonical_license_identity_requires_authority_local_and_version(local_id: str):
    with pytest.raises(ValueError):
        build_canonical_license_identity(
            authority_node_id="de305d54-75b4-431b-adb2-eb6b9e546014",
            local_id=local_id,
            version="1",
        )
