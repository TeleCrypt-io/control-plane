"""Focused tests for the installed tier_controller wheel."""

import asyncio
import inspect
import pathlib
import site
import sys
from types import SimpleNamespace

source_dir = pathlib.Path(__file__).resolve().parent
sys.path[:] = [entry for entry in sys.path if pathlib.Path(entry or ".").resolve() != source_dir]

from synapse.api.errors import Codes
from synapse.module_api import NOT_SPAM
import tier_controller
from tier_controller import (
    MAX_MEDIA_BYTES,
    STORAGE_MARKER,
    TierController,
    _DENIAL_MESSAGE,
)

module_path = pathlib.Path(tier_controller.__file__).resolve()
site_packages = {pathlib.Path(path).resolve() for path in site.getsitepackages()}
if not any(root in module_path.parents for root in site_packages):
    raise RuntimeError(f"tier_controller imported outside site-packages: {module_path}")


class FakeModuleApi:
    def __init__(self, user_types=None, lookup_error=False):
        self.user_types = user_types or {}
        self.lookup_error = lookup_error
        self.registered_media = {}
        self.registered_spam = {}
        self.registered_rules = {}
        self.registered_rates = {}

    def register_media_repository_callbacks(self, **callbacks):
        self.registered_media.update(callbacks)

    def register_spam_checker_callbacks(self, **callbacks):
        self.registered_spam.update(callbacks)

    def register_third_party_rules_callbacks(self, **callbacks):
        self.registered_rules.update(callbacks)

    def register_ratelimit_callbacks(self, **callbacks):
        self.registered_rates.update(callbacks)

    async def get_userinfo_by_id(self, user_id):
        if self.lookup_error:
            raise RuntimeError("native lookup failed")
        if user_id not in self.user_types:
            return None
        return SimpleNamespace(user_type=self.user_types[user_id])


def make_module(user_types=None, lookup_error=False):
    api = FakeModuleApi(user_types, lookup_error)
    return TierController({}, api), api


async def upload(module, user_id, size):
    return await module.is_user_allowed_to_upload_media_of_size(user_id, size)


def event(event_type, sender="@alice:test", content=None, state_key="", is_state=True):
    return SimpleNamespace(
        type=event_type,
        sender=sender,
        state_key=state_key,
        get_content=lambda: content or {},
        is_state=lambda: is_state,
    )


async def test_local_user_type_controls_upload_without_sql_usage_lookup():
    module, api = make_module({"@free:test": "wild", "@paid:test": "verified", "@blocked:test": "uploads_blocked"})
    assert await upload(module, "@free:test", 1) is False
    assert await upload(module, "@paid:test", MAX_MEDIA_BYTES) is True
    assert await upload(module, "@blocked:test", 1) is False
    assert api.registered_media
    assert "on_media_deleted" in api.registered_media
    assert "check_media_file_for_spam" in api.registered_spam
    assert not hasattr(api, "run_db_interaction")


async def test_native_lookup_failure_fails_closed_for_upload_but_encryption_is_native():
    module, _ = make_module(lookup_error=True)
    assert await upload(module, "@paid:test", 1) is False
    assert await module.check_event_for_spam(event("m.room.encryption")) is NOT_SPAM


async def test_media_notifications_use_upload_identity_and_media_only_for_delete():
    module, _ = make_module()
    calls = []

    async def post(path, payload):
        calls.append((path, payload))

    module._post_cashier = post
    await module._notify_upload("@owner:test", "media-1", 42)
    await module._notify_delete("media-1")
    assert calls == [
        ("/internal/cashier/file_upload_webhook", {"user_id": "@owner:test", "media_id": "media-1", "size_bytes": 42}),
        ("/internal/cashier/file_delete_webhook", {"media_id": "media-1"}),
    ]


async def test_paid_user_types_allow_encryption_and_message_rates_are_native():
    module, _ = make_module({"@verified:test": "verified", "@blocked:test": "uploads_blocked"})
    assert await module.check_event_for_spam(event("m.room.encryption", "@verified:test")) is NOT_SPAM
    assert await module.check_event_for_spam(event("m.room.encryption", "@blocked:test")) is NOT_SPAM
    free_module, _ = make_module({"@free:test": "wild"})
    free_rate = await free_module.get_ratelimit_override_for_user("@free:test", "room_message")
    paid_rate = await module.get_ratelimit_override_for_user("@verified:test", "room_message")
    assert (free_rate.per_second, free_rate.burst_count) == (0.5, 10)
    assert (paid_rate.per_second, paid_rate.burst_count) == (1.0, 20)
    assert await module.get_ratelimit_override_for_user("@verified:test", "registration") is None


async def test_free_encrypted_room_is_allowed_before_creation():
    module, _ = make_module({"@free:test": "wild"})
    config = {"initial_state": [{"type": "m.room.encryption", "state_key": "", "content": {}}]}
    assert await module.user_may_create_room("@free:test", config) is NOT_SPAM


async def test_plain_message_is_rejected_for_every_account():
    module, _ = make_module({"@free:test": "wild", "@paid:test": "verified"})
    for user_id in ("@free:test", "@paid:test"):
        assert await module.check_event_for_spam(event("m.room.message", user_id, is_state=False)) == (
            Codes.FORBIDDEN,
            {"error": _DENIAL_MESSAGE},
        )


async def test_plain_room_is_rejected_before_creation():
    module, _ = make_module({"@free:test": "wild"})
    assert await module.user_may_create_room("@free:test", {"initial_state": []}) == (
        Codes.FORBIDDEN,
        {"error": _DENIAL_MESSAGE},
    )


async def test_storage_creation_gets_fixed_owner_readers_permissions_and_marker():
    module, _ = make_module({"@owner:test": "verified"})
    config = {
        "initial_state": [
            {"type": "m.room.create", "state_key": "", "content": {"type": "m.space"}},
            {"type": "org.matrix.msc3088.room.purpose", "state_key": "org.matrix.msc3089.tree", "content": {"org.matrix.msc3088.enabled": True}},
            {"type": "m.room.power_levels", "state_key": "", "content": {"users": {"@attacker:test": 100}, "events": {STORAGE_MARKER: 100}}},
        ]
    }
    requester = SimpleNamespace(user=SimpleNamespace(to_string=lambda: "@owner:test"))
    await module.on_create_room(requester, config, False)
    power = [item for item in config["initial_state"] if item["type"] == "m.room.power_levels"][0]
    assert power["content"]["users"] == {"@owner:test": 100}
    assert power["content"]["users_default"] == 0
    assert power["content"]["ban"] == 100
    assert power["content"]["invite"] == 100
    assert power["content"]["state_default"] == 0
    assert power["content"]["events_default"] == 0
    assert power["content"]["events"]["m.room.name"] == 100
    assert power["content"]["events"]["m.room.message"] == 0
    assert power["content"]["events"]["m.room.message.encrypted"] == 0
    assert power["content"]["events"]["m.sticker"] == 0
    assert power["content"]["events"]["m.space.child"] == 100
    assert power["content"]["events"]["m.space.parent"] == 100
    assert power["content"]["events"][STORAGE_MARKER] == 100


async def test_storage_power_levels_cannot_be_changed_even_by_owner():
    module, _ = make_module({"@owner:test": "verified"})
    fixed = module._fixed_power_levels("@owner:test")
    current = event("m.room.power_levels", content=fixed)
    changed = dict(fixed)
    changed["users"] = {"@owner:test": 100, "@reader:test": 100}
    allowed, error = await module.check_event_allowed(
        event("m.room.power_levels", sender="@owner:test", content=changed),
        {("m.room.power_levels", ""): current},
    )
    assert allowed is False
    assert error == {"error": "Storage room permissions are fixed."}


async def test_storage_sdk_creation_uses_effective_creation_content_and_override():
    module, _ = make_module({"@owner:test": "verified"})
    config = {
        "creation_content": {"type": "m.space"},
        "power_level_content_override": {"events": {STORAGE_MARKER: 100}},
        "initial_state": [],
    }
    requester = SimpleNamespace(user=SimpleNamespace(to_string=lambda: "@owner:test"))
    await module.on_create_room(requester, config, False)
    assert config["power_level_content_override"]["users"] == {"@owner:test": 100}
    assert config["power_level_content_override"]["events"][STORAGE_MARKER] == 100


async def test_unmarked_power_levels_remain_native():
    module, _ = make_module({"@owner:test": "verified"})
    allowed, error = await module.check_event_allowed(
        event("m.room.power_levels", content={"users": {"@owner:test": 100}}),
        {("m.room.power_levels", ""): event("m.room.power_levels", content={"users": {"@owner:test": 100}})},
    )
    assert (allowed, error) == (True, None)


if __name__ == "__main__":
    tests = [value for name, value in globals().items() if name.startswith("test_")]
    failures = 0
    for test in tests:
        try:
            result = test()
            if inspect.isawaitable(result):
                asyncio.run(result)
        except Exception as error:
            failures += 1
            print(f"{test.__name__}: {error}", file=sys.stderr)
    if failures:
        raise SystemExit(f"{failures} of {len(tests)} tests failed")
    print(f"{len(tests)} tests passed")
