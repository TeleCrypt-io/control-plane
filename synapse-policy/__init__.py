"""Native Synapse capability policy for TeleCrypt.

Entitlement state is published by Cashier into Synapse's local ``user_type`` column;
the admission decisions here do not open a database connection or perform a remote
policy lookup. Successful local media mutations send best-effort accounting
notifications to the pod-local Cashier endpoint.
"""

from __future__ import annotations

import json
import logging
import os
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit

from synapse.api.errors import Codes
from synapse.module_api import ModuleApi, NOT_SPAM, make_deferred_yieldable
from synapse.module_api.callbacks.ratelimit_callbacks import RatelimitOverride
from twisted.web.client import readBody
from twisted.web.http_headers import Headers

logger = logging.getLogger(__name__)

FREE = "free"
PAID = "paid"
PAID_OVER_QUOTA = "paid_over_quota"
PAID_USER_TYPES = frozenset((PAID, PAID_OVER_QUOTA))

BYTES_PER_MIB = 1024**2
MAX_MEDIA_BYTES = 128 * BYTES_PER_MIB

# The permission entry is both the MSC3089 branch permission and the storage-room
# marker. Ordinary chat rooms do not contain it.
STORAGE_MARKER = "org.matrix.msc3089.branch"
STORAGE_ROOM_TYPE = "m.space"

# The module config points directly at Cashier's private endpoint, never public ingress.
CASHIER_TOKEN_ENV = "CASHIER_SYNAPSE_TOKEN"
UPLOAD_WEBHOOK_PATH = "/internal/cashier/file_upload_webhook"
DELETE_WEBHOOK_PATH = "/internal/cashier/file_delete_webhook"

FREE_MESSAGE_RATE = 0.5
FREE_MESSAGE_BURST = 10
PAID_MESSAGE_RATE = 1.0
PAID_MESSAGE_BURST = 20

_DENIAL_MESSAGE = (
    "TeleCrypt requires encrypted conversations. "
    "Use an encrypted room or open Plan if this account is suspended."
)
_STORAGE_DENIAL_MESSAGE = (
    "Storage rooms require an active paid capability with uploads enabled. "
    "Open Plan to restore uploads."
)


def _event_type(event: Any) -> str | None:
    if isinstance(event, dict):
        return event.get("type")
    return getattr(event, "type", None) or getattr(event, "event_type", None)


def _event_state_key(event: Any) -> str:
    if isinstance(event, dict):
        return str(event.get("state_key", ""))
    return str(getattr(event, "state_key", ""))


def _event_content(event: Any) -> Mapping[str, Any]:
    if isinstance(event, dict):
        content = event.get("content", {})
    else:
        content = getattr(event, "content", {})
    # Synapse's native events expose JsonObject, including nested objects.
    return content if isinstance(content, Mapping) else {}


class TierController:
    """Apply the local user type to native Synapse policy callbacks."""

    def __init__(self, config: dict[str, Any], api: ModuleApi) -> None:
        for name in ("CASHIER_PLAN_TOKEN", "CASHIER_JANITOR_TOKEN"):
            if name in os.environ:
                raise ValueError(f"{name} must be unset for Synapse")
        cashier_token = os.environ.get(CASHIER_TOKEN_ENV, "")
        if len(cashier_token) != 64 or any(char not in "0123456789abcdef" for char in cashier_token):
            raise ValueError(f"{CASHIER_TOKEN_ENV} must be 64 lowercase hexadecimal characters")
        cashier_internal_url = config.get("cashier_internal_url")
        if not isinstance(cashier_internal_url, str):
            raise ValueError("cashier_internal_url must be an absolute HTTP or HTTPS URL")
        try:
            cashier_endpoint = urlsplit(cashier_internal_url)
            cashier_host = cashier_endpoint.hostname
        except ValueError as error:
            raise ValueError("cashier_internal_url must be an absolute HTTP or HTTPS URL") from error
        if cashier_endpoint.scheme not in ("http", "https") or not cashier_endpoint.netloc or not cashier_host:
            raise ValueError("cashier_internal_url must be an absolute HTTP or HTTPS URL")
        self._api = api
        self._cashier_token = cashier_token
        self._cashier_internal_url = cashier_internal_url.rstrip("/")

        api.register_media_repository_callbacks(
            is_user_allowed_to_upload_media_of_size=self.is_user_allowed_to_upload_media_of_size,
            on_media_uploaded=self.on_media_uploaded,
            on_media_deleted=self.on_media_deleted,
        )
        api.register_ratelimit_callbacks(
            get_ratelimit_override_for_user=self.get_ratelimit_override_for_user,
        )
        api.register_spam_checker_callbacks(
            user_may_create_room=self.user_may_create_room,
            check_event_for_spam=self.check_event_for_spam,
        )

    async def _get_user_type(self, user_id: str) -> str | None:
        """Read Synapse's local user projection through its native module API."""
        try:
            info = await self._api.get_userinfo_by_id(user_id)
        except Exception:
            logger.exception("tier_controller: native user info lookup failed for %s", user_id)
            return None
        if info is None:
            return None
        value = getattr(info, "user_type", None)
        return value if isinstance(value, str) else None

    async def _is_paid(self, user_id: str) -> bool:
        return (await self._get_user_type(user_id)) in PAID_USER_TYPES

    async def is_user_allowed_to_upload_media_of_size(self, user_id: str, size: int) -> bool:
        """Allow admission only for the explicit uploads-enabled local state.

        Team quota and usage belong to Cashier. They are reconciled asynchronously and
        therefore must not be looked up from this request callback.
        """
        if type(size) is not int or size < 0 or size > MAX_MEDIA_BYTES:
            return False
        return await self._get_user_type(user_id) == PAID

    async def get_ratelimit_override_for_user(
        self, user_id: str, limiter_name: str
    ) -> RatelimitOverride | None:
        # Keep Synapse's native limiter selection. Only message actions receive the
        # product's per-user paid/free rates.
        if "message" not in limiter_name.lower():
            return None
        if await self._is_paid(user_id):
            return RatelimitOverride(per_second=PAID_MESSAGE_RATE, burst_count=PAID_MESSAGE_BURST)
        return RatelimitOverride(per_second=FREE_MESSAGE_RATE, burst_count=FREE_MESSAGE_BURST)

    async def user_may_create_room(self, user_id: str, room_config: dict[str, Any]) -> Any:
        if self._is_storage_creation(room_config):
            if await self._get_user_type(user_id) != PAID:
                return Codes.FORBIDDEN, {"error": _STORAGE_DENIAL_MESSAGE}
            return NOT_SPAM

        # Synapse does not send createRoom initial_state events through the event spam
        # callback. Every room must declare encryption before it is created, including Free.
        initial_state = room_config.get("initial_state", [])
        if not isinstance(initial_state, list) or not any(
            _event_type(event) == "m.room.encryption" and _event_state_key(event) == ""
            for event in initial_state
        ):
            return Codes.FORBIDDEN, {"error": _DENIAL_MESSAGE}
        return NOT_SPAM

    async def check_event_for_spam(self, event: Any) -> Any:
        is_state = getattr(event, "is_state", lambda: False)
        if _event_type(event) in ("m.room.message", "m.sticker") and not is_state():
            return Codes.FORBIDDEN, {"error": _DENIAL_MESSAGE}
        return NOT_SPAM

    async def on_media_uploaded(self, user_id: str, media_id: str, size_bytes: int) -> None:
        """Account for a local upload after Synapse commits its media metadata."""
        await self._notify_upload(user_id, media_id, size_bytes)

    async def on_media_deleted(self, media_id: str) -> None:
        """Account for a completed deletion using only the stable media ID."""
        if not isinstance(media_id, str) or not media_id:
            return
        await self._notify_delete(media_id)

    async def _notify_upload(self, user_id: str, media_id: str, size_bytes: int) -> None:
        try:
            await self._post_cashier(
                UPLOAD_WEBHOOK_PATH,
                {"user_id": user_id, "media_id": media_id, "size_bytes": size_bytes},
            )
        except Exception:
            logger.exception(
                "tier_controller: upload committed but Cashier accounting notification failed; "
                "the upload was not rolled back: media_id=%s",
                media_id,
            )

    async def _notify_delete(self, media_id: str) -> None:
        try:
            await self._post_cashier(DELETE_WEBHOOK_PATH, {"media_id": media_id})
        except Exception:
            logger.exception(
                "tier_controller: deletion committed but Cashier accounting notification failed; "
                "the deletion was not rolled back: media_id=%s",
                media_id,
            )

    async def _post_cashier(self, path: str, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        response = await self._api.http_client.request(
            "POST",
            self._cashier_internal_url + path,
            data=body,
            headers=Headers({
                b"Content-Type": [b"application/json"],
                b"Authorization": [b"Bearer " + self._cashier_token.encode("ascii")],
            }),
        )
        response_body = await make_deferred_yieldable(readBody(response))
        if not 200 <= response.code < 300:
            raise RuntimeError(
                f"Cashier notification returned HTTP {response.code}: "
                f"{response_body[:256].decode('utf-8', errors='replace')}"
            )

    @staticmethod
    def _is_storage_creation(room_config: dict[str, Any]) -> bool:
        initial_state = room_config.get("initial_state", [])
        if not isinstance(initial_state, list):
            initial_state = []
        power_levels = None
        room_create = room_config.get("creation_content")
        storage_purpose = False
        encrypted = False
        for event in initial_state:
            event_type = _event_type(event)
            if event_type == "m.room.create" and _event_state_key(event) == "":
                room_create = _event_content(event)
            elif event_type == "m.room.power_levels" and _event_state_key(event) == "":
                power_levels = _event_content(event)
            elif (
                event_type == "org.matrix.msc3088.room.purpose"
                and _event_state_key(event) == "org.matrix.msc3089.tree"
                and _event_content(event).get("org.matrix.msc3088.enabled") is True
            ):
                storage_purpose = True
            elif event_type == "m.room.encryption" and _event_state_key(event) == "":
                encrypted = True
        if not isinstance(room_create, dict) or room_create.get("type") != STORAGE_ROOM_TYPE:
            return False
        if not storage_purpose or not encrypted:
            return False
        if power_levels is None:
            power_levels = room_config.get("power_level_content_override")
        marker_events = power_levels.get("events", {}) if isinstance(power_levels, dict) else {}
        marker_level = marker_events.get(STORAGE_MARKER) if isinstance(marker_events, dict) else None
        return type(marker_level) in (int, float) and 0 <= marker_level <= 100
