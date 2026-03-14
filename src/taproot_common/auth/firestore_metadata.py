"""Firestore metadata store for API key ID to store/tenant ID mapping."""

import logging
from typing import Any, Dict, Optional

from taproot_common.auth.metadata import MetadataStore

logger = logging.getLogger(__name__)


class FirestoreMetadataStore(MetadataStore):
    """Google Cloud Firestore-backed metadata store.

    Collection schema:
        - Document ID: api_key_id (SHA-256 hash of raw API key)
        - Fields: api_key_id (str), store_id (str), name (str), created_at (str)

    Uses async Firestore client with Application Default Credentials.
    The client is initialized lazily on first call to avoid blocking at import time.
    """

    def __init__(self, project_id: str, database: str, collection: str) -> None:
        self._project_id = project_id
        self._database = database
        self._collection_name = collection
        self._collection_ref: Any = None

    async def _get_collection(self) -> Any:
        """Lazily initialize and return the Firestore collection reference."""
        if self._collection_ref is None:
            from google.cloud.firestore_v1 import AsyncClient

            client = AsyncClient(project=self._project_id, database=self._database)
            self._collection_ref = client.collection(self._collection_name)
        return self._collection_ref

    async def get_store_id(self, api_key_id: str) -> Optional[str]:
        logger.info("auth.metadata.firestore.lookup", extra={"api_key_id": api_key_id})
        try:
            collection = await self._get_collection()
            doc = await collection.document(api_key_id).get()
        except Exception as e:
            if _is_not_found(e):
                logger.warning(
                    "auth.metadata.firestore.not_found",
                    extra={"api_key_id": api_key_id},
                )
                return None
            logger.error(
                "auth.metadata.firestore.error",
                extra={"api_key_id": api_key_id, "error": str(e)},
            )
            raise
        if not doc.exists:
            logger.warning(
                "auth.metadata.firestore.not_found",
                extra={"api_key_id": api_key_id},
            )
            return None
        logger.info("auth.metadata.firestore.found", extra={"api_key_id": api_key_id})
        return doc.to_dict().get("store_id")

    async def get_metadata(self, api_key_id: str) -> Optional[Dict[str, Any]]:
        logger.info("auth.metadata.firestore.lookup", extra={"api_key_id": api_key_id})
        try:
            collection = await self._get_collection()
            doc = await collection.document(api_key_id).get()
        except Exception as e:
            if _is_not_found(e):
                logger.warning(
                    "auth.metadata.firestore.not_found",
                    extra={"api_key_id": api_key_id},
                )
                return None
            logger.error(
                "auth.metadata.firestore.error",
                extra={"api_key_id": api_key_id, "error": str(e)},
            )
            raise
        if not doc.exists:
            logger.warning(
                "auth.metadata.firestore.not_found",
                extra={"api_key_id": api_key_id},
            )
            return None
        logger.info("auth.metadata.firestore.found", extra={"api_key_id": api_key_id})
        return dict(doc.to_dict())


def _is_not_found(exc: Exception) -> bool:
    """Check if an exception is a Firestore 'not found' error."""
    try:
        from google.api_core.exceptions import NotFound

        return isinstance(exc, NotFound)
    except ImportError:
        return False
