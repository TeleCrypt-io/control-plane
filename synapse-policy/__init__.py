# tier_controller — fail-closed capability restrictions for unverified users.
#
# Installed by the standalone Synapse server container image from the exact wheel release and loaded by
# Synapse's `modules:` configuration. It is not copied into the Controlplane image. Inverted tier
# model: everyone is RESTRICTED (no uploads,
# a capped number of created rooms, no m.room.encryption) unless user_type == 'verified'.
# NULL/absent user_type (the default for a freshly registered account, agent or human) is
# restricted; only an explicit 'verified' user_type lifts the restriction. Verified uploads also
# obey the fixed per-file and per-user original-media limits below.
#
# Callback signatures + return-value handling verified against the exact Synapse 1.159.0 package:
#   - media_repository_callbacks.is_user_allowed_to_upload_media_of_size(user_id, size) -> bool.
#   - spamchecker_callbacks.user_may_create_room(user_id, room_config) accepts NOT_SPAM, Codes,
#     (Codes, dict), or bool.
#   - spamchecker_callbacks.check_event_for_spam(event) accepts NOT_SPAM, Codes, (Codes, dict),
#     or str. We use the tuple form to provide the client-visible error message.
from __future__ import annotations

import logging
from typing import Any

from synapse.api.errors import Codes
from synapse.module_api import ModuleApi, NOT_SPAM
from synapse.module_api.errors import ConfigError

logger = logging.getLogger(__name__)

VERIFIED = "verified"

BYTES_PER_MIB = 1024**2
BYTES_PER_GIB = 1024**3

# Synapse's max_upload_size is the primary per-file limit. Keep the same bound here so the
# callback cannot admit a request that the surrounding media path is not meant to process.
MAX_MEDIA_BYTES = 128 * BYTES_PER_MIB
MAX_USER_MEDIA_BYTES = 50 * BYTES_PER_GIB

_DENIAL_MESSAGE = (
    "This account needs an active paid team seat for uploads, encryption, and additional rooms. "
    "Ask your team's paying owner to assign a seat or restore access in Plan at "
    "https://telecrypt.io/plan. "
    "See https://www.telecrypt.io/llms.txt"
)


class TierControllerConfig:
    def __init__(self, restricted_room_cap: int) -> None:
        self.restricted_room_cap = restricted_room_cap


class TierController:
    def __init__(self, config: TierControllerConfig, api: ModuleApi) -> None:
        self.config = config
        self._run_db_interaction = api.run_db_interaction

        api.register_media_repository_callbacks(
            is_user_allowed_to_upload_media_of_size=self.is_user_allowed_to_upload_media_of_size,
        )
        api.register_spam_checker_callbacks(
            user_may_create_room=self.user_may_create_room,
            check_event_for_spam=self.check_event_for_spam,
        )

    @staticmethod
    def parse_config(config: dict[str, Any]) -> TierControllerConfig:
        try:
            restricted_room_cap = int(config.get("restricted_room_cap", 3))
        except (TypeError, ValueError) as e:
            raise ConfigError("restricted_room_cap must be an integer") from e
        if restricted_room_cap < 0:
            raise ConfigError("restricted_room_cap must not be negative")

        return TierControllerConfig(restricted_room_cap)

    async def _get_user_type(self, user_id: str) -> str | None:
        def txn(cursor: Any) -> str | None:
            cursor.execute("SELECT user_type FROM users WHERE name = %s", (user_id,))
            row = cursor.fetchone()
            return row[0] if row else None

        try:
            user_type = await self._run_db_interaction(
                "tier_controller_get_user_type", txn
            )
        except Exception:
            logger.exception(
                "tier_controller: user_type lookup failed for %s, failing closed", user_id
            )
            return None

        return user_type

    async def _is_restricted(self, user_id: str) -> bool:
        return await self._get_user_type(user_id) != VERIFIED

    async def _count_created_rooms(self, user_id: str) -> int:
        def txn(cursor: Any) -> int:
            cursor.execute("SELECT count(*) FROM rooms WHERE creator = %s", (user_id,))
            row = cursor.fetchone()
            return int(row[0]) if row else 0

        try:
            return await self._run_db_interaction(
                "tier_controller_count_created_rooms", txn
            )
        except Exception:
            logger.exception(
                "tier_controller: room count lookup failed for %s, failing closed", user_id
            )
            return self.config.restricted_room_cap

    async def _get_upload_snapshot(self, user_id: str) -> tuple[str | None, Any]:
        """Read the verified projection and original-media usage in one DB interaction."""

        def txn(cursor: Any) -> tuple[str | None, Any]:
            cursor.execute("SELECT user_type FROM users WHERE name = %s", (user_id,))
            user_row = cursor.fetchone()
            user_type = user_row[0] if user_row else None
            if user_type != VERIFIED:
                return user_type, None

            # URL-preview rows share this table but are not user-uploaded originals. Thumbnails,
            # remote media, deleted rows, and staging files are outside this query by design.
            cursor.execute(
                # PostgreSQL returns SUM(bigint) as numeric. Cast the bounded result back to a
                # BIGINT so the callback's strict integer validation sees the same value as
                # Synapse's media metadata API, while an overflowing/malformed sum still fails
                # closed through the database interaction error path.
                "SELECT COALESCE(SUM(media_length), 0)::BIGINT "
                "FROM local_media_repository "
                "WHERE user_id = %s AND url_cache IS NULL",
                (user_id,),
            )
            usage_row = cursor.fetchone()
            return user_type, usage_row[0] if usage_row else None

        try:
            snapshot = await self._run_db_interaction(
                "tier_controller_get_upload_snapshot", txn
            )
        except Exception:
            logger.exception(
                "tier_controller: upload policy lookup failed for %s, failing closed", user_id
            )
            return None, None

        return snapshot

    @staticmethod
    def _nonnegative_integer(value: Any) -> int | None:
        if type(value) is not int or value < 0:
            return None
        return value

    async def is_user_allowed_to_upload_media_of_size(self, user_id: str, size: int) -> bool:
        proposed_size = self._nonnegative_integer(size)
        if proposed_size is None or proposed_size > MAX_MEDIA_BYTES:
            return False

        user_type, current_usage = await self._get_upload_snapshot(user_id)
        if user_type != VERIFIED:
            return False
        usage = self._nonnegative_integer(current_usage)
        if usage is None or usage > MAX_USER_MEDIA_BYTES:
            return False
        return usage + proposed_size <= MAX_USER_MEDIA_BYTES

    async def user_may_create_room(self, user_id: str, room_config: dict) -> Any:
        if not await self._is_restricted(user_id):
            return NOT_SPAM
        # Synapse does not run createRoom's initial_state events through check_event_for_spam.
        # The user_may_create_room callback receives the complete request body, so reject an
        # encryption state event here before the room is created.
        initial_state = room_config.get("initial_state", [])
        if isinstance(initial_state, list) and any(
            isinstance(event, dict) and event.get("type") == "m.room.encryption"
            for event in initial_state
        ):
            return Codes.FORBIDDEN, {"error": _DENIAL_MESSAGE}
        count = await self._count_created_rooms(user_id)
        if count >= self.config.restricted_room_cap:
            return Codes.FORBIDDEN, {"error": _DENIAL_MESSAGE}
        return NOT_SPAM

    async def check_event_for_spam(self, event: Any) -> Any:
        if event.type != "m.room.encryption" or not event.is_state():
            return NOT_SPAM
        if await self._is_restricted(event.sender):
            return Codes.FORBIDDEN, {"error": _DENIAL_MESSAGE}
        return NOT_SPAM
