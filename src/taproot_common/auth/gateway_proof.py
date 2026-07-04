"""Gateway shared-secret proof check (WO-012 T1b).

APIM injects ``X-Taproot-Gateway-Secret`` on gateway-proxied service routes
(taproot-infra ``apim/aws``); the reserved-header WAF denies client-supplied
copies. An in-VPC caller that bypasses the gateway cannot present the value,
so this check is the application-layer backstop for the open network posture
documented in ``taproot-infra/docs/network-posture-aws.md``.

Rollout is accept-then-enforce via ``TAPROOT_GATEWAY_PROOF_MODE``:
``off`` (skip), ``observe`` (default — log mismatches, allow), ``enforce``
(401 on mismatch, 503 fail-closed if the expected secret cannot be loaded).

The expected value is read from the cloud secret manager under the canonical
name ``taproot-<environment>-gateway-shared-secret`` — never from an env var,
per the platform metadata-only secret rule.
"""

import hmac
import logging
import threading
from typing import Dict, Optional

from fastapi import HTTPException, status

from taproot_common.config import TaprootSettings

logger = logging.getLogger(__name__)

GATEWAY_SECRET_HEADER = "x-taproot-gateway-secret"

_MODES = ("off", "observe", "enforce")

_lock = threading.Lock()
_secret_loaded = False
_expected_secret: Optional[str] = None
_unconfigured_logged = False


def gateway_secret_name(*, environment: str) -> str:
    return f"taproot-{environment}-gateway-shared-secret"


def _load_expected_secret(settings: TaprootSettings) -> Optional[str]:
    from taproot_common.secrets import load_secret

    try:
        value = load_secret(gateway_secret_name(environment=settings.environment))
    except Exception as exc:
        logger.warning(
            "auth.gateway_proof.secret_load_failed",
            extra={"error": str(exc)},
        )
        return None
    return value or None


def _get_expected_secret(settings: TaprootSettings) -> Optional[str]:
    global _secret_loaded, _expected_secret
    with _lock:
        if not _secret_loaded:
            _expected_secret = _load_expected_secret(settings)
            _secret_loaded = True
        return _expected_secret


def reset_gateway_proof_state() -> None:
    """Reset cached secret + log-once state (for testing)."""
    global _secret_loaded, _expected_secret, _unconfigured_logged
    with _lock:
        _secret_loaded = False
        _expected_secret = None
        _unconfigured_logged = False


def verify_gateway_proof(headers: Dict[str, str]) -> None:
    """Check the gateway proof header against the shared secret.

    Args:
        headers: request headers with lowercase keys.

    Raises:
        HTTPException 401: enforce mode and the proof is missing or wrong.
        HTTPException 503: enforce mode and the expected secret is unavailable
            (fail closed rather than silently accepting unproofed traffic).
    """
    global _unconfigured_logged

    settings = TaprootSettings()
    mode = settings.gateway_proof_mode.strip().lower()
    if mode not in _MODES:
        logger.warning(
            "auth.gateway_proof.invalid_mode",
            extra={"mode": mode, "fallback": "observe"},
        )
        mode = "observe"
    if mode == "off":
        return

    expected = _get_expected_secret(settings)
    if expected is None:
        if mode == "enforce":
            logger.error("auth.gateway_proof.unconfigured", extra={"mode": mode})
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Gateway proof enforcement is enabled but the shared secret is unavailable",
            )
        if not _unconfigured_logged:
            logger.warning("auth.gateway_proof.unconfigured", extra={"mode": mode})
            _unconfigured_logged = True
        return

    presented = headers.get(GATEWAY_SECRET_HEADER, "")
    if hmac.compare_digest(presented.encode(), expected.encode()):
        return

    if mode == "enforce":
        logger.warning(
            "auth.gateway_proof.rejected",
            extra={"header_present": bool(presented)},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Request did not carry a valid gateway proof",
        )

    logger.warning(
        "auth.gateway_proof.mismatch",
        extra={"mode": mode, "header_present": bool(presented)},
    )
