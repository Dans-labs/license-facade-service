from __future__ import annotations

from enum import Enum


class PublicLicenseScope(str, Enum):
    LOCAL = "local"
    FEDERATED = "federated"
    SPDX_SUBMISSION = "spdx-submission"


class FederationStatus(str, Enum):
    NOT_PUBLISHED = "not_published"
    PENDING = "pending"
    PUBLISHED = "published"
    PUBLICATION_FAILED = "publication_failed"
    DEPRECATED = "deprecated"
    TOMBSTONED = "tombstoned"


class SpdxSubmissionStatus(str, Enum):
    NOT_REQUESTED = "not_requested"
    READY_FOR_REVIEW = "ready_for_review"


class CustomLicenceLifecycleStatus(str, Enum):
    REGISTERED = "registered"
    DEPRECATED = "deprecated"
    WITHDRAWN = "withdrawn"
    TOMBSTONED = "tombstoned"


CREATION_RULES = {
    PublicLicenseScope.LOCAL: (FederationStatus.NOT_PUBLISHED, SpdxSubmissionStatus.NOT_REQUESTED),
    PublicLicenseScope.FEDERATED: (FederationStatus.PENDING, SpdxSubmissionStatus.NOT_REQUESTED),
    PublicLicenseScope.SPDX_SUBMISSION: (FederationStatus.NOT_PUBLISHED, SpdxSubmissionStatus.READY_FOR_REVIEW),
}

__all__ = [
    "CREATION_RULES",
    "CustomLicenceLifecycleStatus",
    "FederationStatus",
    "PublicLicenseScope",
    "SpdxSubmissionStatus",
]
