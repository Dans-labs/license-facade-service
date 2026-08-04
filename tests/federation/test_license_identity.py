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


@pytest.mark.parametrize("local_id", ["", "   "])
def test_canonical_license_identity_requires_authority_local_and_version(local_id: str):
    with pytest.raises(ValueError):
        build_canonical_license_identity(
            authority_node_id="de305d54-75b4-431b-adb2-eb6b9e546014",
            local_id=local_id,
            version="1",
        )
