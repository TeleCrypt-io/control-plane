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
from typing import Any

from synapse.api.errors import Codes
from synapse.module_api import ModuleApi, NOT_SPAM, make_deferred_yieldable
from synapse.module_api.callbacks.ratelimit_callbacks import RatelimitOverride
from twisted.web.client import readBody
from twisted.web.http_headers import Headers

logger = logging.getLogger(__name__)

WILD = "wild"
VERIFIED = "verified"
UPLOADS_BLOCKED = "uploads_blocked"
PAID_USER_TYPES = frozenset((VERIFIED, UPLOADS_BLOCKED))

BYTES_PER_MIB = 1024**2
MAX_MEDIA_BYTES = 128 * BYTES_PER_MIB

# The permission entry is both the MSC3089 branch permission and the storage-room
# marker. Ordinary chat rooms do not contain it.
STORAGE_MARKER = "org.matrix.msc3089.branch"
STORAGE_ROOM_TYPE = "m.space"

# Cashier is a private same-pod endpoint. Keep this fixed until a native Synapse
# module configuration field exists; this module never sends these notifications via
# the public ingress.
CASHIER_INTERNAL_URL = "http://127.0.0.1:9011"
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


def _event_content(event: Any) -> dict[str, Any]:
    if isinstance(event, dict):
        content = event.get("content", {})
    else:
        getter = getattr(event, "get_content", None)
        content = getter() if getter is not None else getattr(event, "content", {})
    return content if isinstance(content, dict) else {}


def _event_sender(event: Any) -> str:
    if isinstance(event, dict):
        return str(event.get("sender", ""))
    return str(getattr(event, "sender", ""))


def _requester_user_id(requester: Any) -> str:
    user = getattr(requester, "user", requester)
    to_string = getattr(user, "to_string", None)
    if to_string is not None:
        return str(to_string())
    return str(user)


def _state_event(state_events: Any, event_type: str, state_key: str = "") -> Any:
    if not state_events:
        return None
    if isinstance(state_events, dict):
        value = state_events.get((event_type, state_key))
        if value is not None:
            return value
        value = state_events.get(event_type)
        if isinstance(value, dict):
            return value.get(state_key)
        if value is not None and state_key == "":
            return value
    return None


class TierController:
    """Apply the local user type to native Synapse policy callbacks."""

    def __init__(self, _config: dict[str, Any], api: ModuleApi) -> None:
        for name in ("CASHIER_PLAN_TOKEN", "CASHIER_JANITOR_TOKEN"):
            if name in os.environ:
                raise ValueError(f"{name} must be unset for Synapse")
        cashier_token = os.environ.get(CASHIER_TOKEN_ENV, "")
        if len(cashier_token) != 64 or any(char not in "0123456789abcdef" for char in cashier_token):
            raise ValueError(f"{CASHIER_TOKEN_ENV} must be 64 lowercase hexadecimal characters")
        self._api = api
        self._cashier_token = cashier_token

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
        api.register_third_party_rules_callbacks(
            on_create_room=self.on_create_room,
            check_event_allowed=self.check_event_allowed,
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
        return await self._get_user_type(user_id) == VERIFIED

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
            if await self._get_user_type(user_id) != VERIFIED:
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
            CASHIER_INTERNAL_URL + path,
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
        for event in initial_state:
            event_type = _event_type(event)
            if event_type == "m.room.create" and _event_state_key(event) == "":
                room_create = _event_content(event)
            elif event_type == "m.room.power_levels" and _event_state_key(event) == "":
                power_levels = _event_content(event)
        if not isinstance(room_create, dict) or room_create.get("type") != STORAGE_ROOM_TYPE:
            return False
        if power_levels is None:
            power_levels = room_config.get("power_level_content_override")
        marker_events = power_levels.get("events", {}) if isinstance(power_levels, dict) else {}
        return marker_events.get(STORAGE_MARKER) == 100

    @staticmethod
    def _fixed_power_levels(owner: str) -> dict[str, Any]:
        return {
            "ban": 100,
            "events": {
                "m.room.name": 100,
                "m.room.message": 0,
                "m.room.message.encrypted": 0,
                "m.sticker": 0,
                "m.space.child": 100,
                "m.space.parent": 100,
                "m.room.power_levels": 100,
                STORAGE_MARKER: 100,
            },
            "events_default": 0,
            "invite": 100,
            "kick": 100,
            "redact": 100,
            "state_default": 0,
            "users": {owner: 100},
            "users_default": 0,
        }

    async def on_create_room(
        self, requester: Any, room_config: dict[str, Any], is_requester_admin: bool
    ) -> None:
        """Canonicalize storage permissions before Synapse persists the room."""
        if not self._is_storage_creation(room_config):
            return
        owner = _requester_user_id(requester)
        fixed = self._fixed_power_levels(owner)
        room_config["power_level_content_override"] = fixed
        initial_state = room_config.get("initial_state")
        if not isinstance(initial_state, list):
            initial_state = []
        if any(
            _event_type(event) == "m.room.power_levels" and _event_state_key(event) == ""
            for event in initial_state
        ):
            room_config["initial_state"] = [
                (
                    {
                        "type": "m.room.power_levels",
                        "state_key": "",
                        "content": fixed,
                    }
                    if _event_type(event) == "m.room.power_levels" and _event_state_key(event) == ""
                    else event
                )
                for event in initial_state
            ]

    async def check_event_allowed(
        self, event: Any, state_events: Any
    ) -> tuple[bool, dict[str, Any] | None]:
        """Keep storage power levels immutable, including for the creator."""
        if _event_type(event) != "m.room.power_levels" or _event_state_key(event) != "":
            return True, None
        current = _state_event(state_events, "m.room.power_levels", "")
        current_content = _event_content(current)
        marker_events = current_content.get("events", {})
        if not isinstance(marker_events, dict) or marker_events.get(STORAGE_MARKER) != 100:
            return True, None
        users = current_content.get("users")
        if not isinstance(users, dict) or len(users) != 1:
            return False, {"error": "Storage room permissions are invalid."}
        owner, owner_level = next(iter(users.items()))
        if owner_level != 100 or _event_content(event) != self._fixed_power_levels(str(owner)):
            return False, {"error": "Storage room permissions are fixed."}
        return True, None
