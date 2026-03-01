"""Authentication data models."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional


class CloudProvider(str, Enum):
    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"
    LOCAL = "local"


@dataclass
class AuthContext:
    """Authentication context extracted from API Gateway headers.

    Attributes:
        api_key_id: The API key identifier assigned by the API Gateway.
        store_id: The store/tenant identifier looked up from metadata.
        project_id: The Front-S project slug identifier this key belongs to.
        provider: The cloud provider that supplied the identity.
        metadata: Additional metadata from the lookup (e.g., name, created_at).
    """

    api_key_id: str
    store_id: Optional[str] = None
    project_id: Optional[str] = None
    provider: CloudProvider = CloudProvider.LOCAL
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_admin(self) -> bool:
        """Whether this API key has admin privileges."""
        value = self.metadata.get("is_admin", False)
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.lower() in ("true", "1", "yes")
        return bool(value)
