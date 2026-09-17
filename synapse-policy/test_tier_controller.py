"""Unit tests for the installed tier_controller wheel against the exact Synapse runtime."""
import asyncio
import inspect
import pathlib
import site
import sys
from types import SimpleNamespace

# Running this file from the source checkout would otherwise put the source package ahead of the
# wheel under test. CI mounts this file separately and installs the wheel into site-packages.
source_dir = pathlib.Path(__file__).resolve().parent
sys.path[:] = [entry for entry in sys.path if pathlib.Path(entry or ".").resolve() != source_dir]

from synapse.api.errors import Codes
from synapse.module_api import NOT_SPAM
import tier_controller
from tier_controller import (
    MAX_MEDIA_BYTES,
    MAX_USER_MEDIA_BYTES,
    TierController,
    _DENIAL_MESSAGE,
)

module_path = pathlib.Path(tier_controller.__file__).resolve()
site_packages = {pathlib.Path(path).resolve() for path in site.getsitepackages()}
if not any(root in module_path.parents for root in site_packages):
    raise RuntimeError(f"tier_controller imported outside site-packages: {module_path}")


class FakeModuleApi:
    """Duck-typed stand-in for synapse.module_api.ModuleApi."""

    def __init__(
        self,
        user_types: dict,
        media_usage: dict,
        db_error: bool = False,
    ):
        self.user_types = user_types
        self.media_usage = media_usage
        self.db_error = db_error
        self.db_calls = []
        self.queries = []
        self.registered_media = {}
        self.registered_spam = {}

    def register_media_repository_callbacks(self, **callbacks):
        self.registered_media.update(callbacks)

    def register_spam_checker_callbacks(self, **callbacks):
        self.registered_spam.update(callbacks)

    async def run_db_interaction(self, desc, func):
        self.db_calls.append(desc)
        if self.db_error:
            raise RuntimeError("simulated db failure")
        if desc == "tier_controller_get_user_type":
            return _run_user_type(self, func)
        if desc == "tier_controller_get_upload_snapshot":
            return _run_upload_snapshot(self, func)
        raise AssertionError(f"unexpected desc {desc}")


def _run_user_type(api, func):
    class RecordingCursor:
        def __init__(self, table):
            self.table = table

        def execute(self, sql, args):
            self.user_id = args[0]
            api.queries.append((sql, args))

        def fetchone(self):
            val = self.table.get(self.user_id, "__missing__")
            if val == "__missing__":
                return None
            return (val,)

    return func(RecordingCursor(api.user_types))


def _run_upload_snapshot(api, func):
    class RecordingCursor:
        def __init__(self):
            self.user_id = None
            self.query = ""

        def execute(self, sql, args):
            self.query = sql
            self.user_id = args[0]
            api.queries.append((sql, args))

        def fetchone(self):
            if "SELECT user_type" in self.query:
                val = api.user_types.get(self.user_id, "__missing__")
                return None if val == "__missing__" else (val,)
            return (api.media_usage.get(self.user_id, 0),)

    return func(RecordingCursor())


def make_module(
    user_types=None,
    media_usage=None,
    db_error=False,
):
    api = FakeModuleApi(
        user_types or {}, media_usage or {}, db_error=db_error
    )
    module = TierController({}, api)
    return module, api


async def upload_decision(module, user_id, size):
    return await module.is_user_allowed_to_upload_media_of_size(user_id, size)


def make_event(event_type, sender, is_state=True):
    return SimpleNamespace(type=event_type, sender=sender, is_state=lambda: is_state)


async def test_unverified_denied_upload():
    module, _ = make_module(user_types={"@a:x": "unverified"})
    assert await upload_decision(module, "@a:x", 100) is False


async def test_verified_allowed_upload():
    module, _ = make_module(user_types={"@a:x": "verified"})
    assert await upload_decision(module, "@a:x", 100) is True


async def test_null_type_denied_upload():
    module, _ = make_module(user_types={"@a:x": None})
    assert await upload_decision(module, "@a:x", 100) is False


async def test_unknown_legacy_type_denied_upload():
    module, _ = make_module(user_types={"@a:x": "paid_agent"})
    assert await upload_decision(module, "@a:x", 100) is False


async def test_upload_boundaries():
    module, _ = make_module(user_types={"@a:x": "verified"})
    assert await upload_decision(module, "@a:x", 0) is True
    assert await upload_decision(
        module, "@a:x", MAX_MEDIA_BYTES - 1
    ) is True
    assert await upload_decision(module, "@a:x", MAX_MEDIA_BYTES) is True
    assert await upload_decision(module, "@a:x", MAX_MEDIA_BYTES + 1) is False


async def test_upload_quota_boundaries():
    module, _ = make_module(
        user_types={"@a:x": "verified"},
        media_usage={"@a:x": MAX_USER_MEDIA_BYTES - 1},
    )
    assert await upload_decision(module, "@a:x", 1) is True
    assert await upload_decision(module, "@a:x", 2) is False

    module, _ = make_module(
        user_types={"@a:x": "verified"},
        media_usage={"@a:x": MAX_USER_MEDIA_BYTES},
    )
    assert await upload_decision(module, "@a:x", 0) is True
    assert await upload_decision(module, "@a:x", 1) is False


async def test_upload_rejects_negative_size_or_usage():
    module, _ = make_module(
        user_types={"@a:x": "verified"}, media_usage={"@a:x": -1}
    )
    assert await upload_decision(module, "@a:x", 1) is False

    module, _ = make_module(user_types={"@a:x": "verified"})
    assert await upload_decision(module, "@a:x", -1) is False


async def test_unverified_encrypted_initial_state_denied_before_room_creation():
    module, _ = make_module(
        user_types={"@a:x": "unverified"}
    )
    room_config = {
        "preset": "private_chat",
        "initial_state": [
            {
                "type": "m.room.encryption",
                "state_key": "",
                "content": {"algorithm": "m.megolm.v1.aes-sha2"},
            }
        ],
    }
    assert await module.user_may_create_room("@a:x", room_config) == (
        Codes.FORBIDDEN,
        {"error": _DENIAL_MESSAGE},
    )


async def test_verified_encrypted_initial_state_allowed():
    module, _ = make_module(user_types={"@a:x": "verified"})
    room_config = {
        "initial_state": [
            {
                "type": "m.room.encryption",
                "state_key": "",
                "content": {"algorithm": "m.megolm.v1.aes-sha2"},
            }
        ],
    }
    assert await module.user_may_create_room("@a:x", room_config) is NOT_SPAM


async def test_unverified_unencrypted_room_is_allowed():
    module, api = make_module(user_types={"@a:x": "unverified"})
    assert await module.user_may_create_room("@a:x", {}) is NOT_SPAM
    assert api.db_calls == ["tier_controller_get_user_type"]


async def test_unverified_encryption_denied():
    module, _ = make_module(user_types={"@a:x": "unverified"})
    assert await module.check_event_for_spam(make_event("m.room.encryption", "@a:x")) == (
        Codes.FORBIDDEN,
        {"error": _DENIAL_MESSAGE},
    )


async def test_verified_encryption_allowed():
    module, _ = make_module(user_types={"@a:x": "verified"})
    assert await module.check_event_for_spam(make_event("m.room.encryption", "@a:x")) is NOT_SPAM


async def test_null_type_encryption_denied():
    module, _ = make_module(user_types={"@a:x": None})
    assert await module.check_event_for_spam(make_event("m.room.encryption", "@a:x")) == (
        Codes.FORBIDDEN,
        {"error": _DENIAL_MESSAGE},
    )


async def test_non_encryption_event_ignored():
    module, _ = make_module(user_types={"@a:x": "unverified"})
    assert await module.check_event_for_spam(make_event("m.room.message", "@a:x")) is NOT_SPAM


async def test_encryption_event_non_state_ignored():
    module, _ = make_module(user_types={"@a:x": "unverified"})
    assert await module.check_event_for_spam(
        make_event("m.room.encryption", "@a:x", is_state=False)
    ) is NOT_SPAM


async def test_db_error_fails_closed_on_upload():
    module, _ = make_module(user_types={"@a:x": "verified"}, db_error=True)
    assert await upload_decision(module, "@a:x", 100) is False


async def test_db_error_still_allows_unencrypted_room_creation():
    module, _ = make_module(user_types={"@a:x": "verified"}, db_error=True)
    assert await module.user_may_create_room("@a:x", {}) is NOT_SPAM


async def test_user_type_grant_and_revocation_are_visible_immediately():
    module, api = make_module(user_types={"@a:x": None})
    assert await upload_decision(module, "@a:x", 100) is False

    api.user_types["@a:x"] = "verified"
    assert await upload_decision(module, "@a:x", 100) is True

    api.user_types["@a:x"] = None
    assert await upload_decision(module, "@a:x", 100) is False


async def test_db_error_recovers_on_next_decision():
    module, api = make_module(user_types={"@a:x": "verified"}, db_error=True)
    assert await upload_decision(module, "@a:x", 100) is False

    api.db_error = False
    assert await upload_decision(module, "@a:x", 100) is True


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
