#!/usr/bin/env bash
# shellcheck disable=SC2016
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
url_helper="$repo_root/scripts/check-release-source_helpers.sh"
tier_controller_pyproject="$repo_root/synapse-policy/pyproject.toml"

# Exercise helper implementations with bounded synthetic inputs. Workflow contract checks belong
# in the workflow itself; duplicating its source text here only makes harmless refactors fail.
temporary="$(mktemp -d)"
trap 'rm -rf -- "$temporary"' EXIT
source "$repo_root/scripts/release-helpers.sh"
project_version="$(sed -n 's/^version = "\([^"]*\)"$/\1/p' "$tier_controller_pyproject")"
test -n "$project_version"

test_digest='sha256:0000000000000000000000000000000000000000000000000000000000000000'
binding_image_digest='sha256:1111111111111111111111111111111111111111111111111111111111111111'
jq -cn --arg digest "$binding_image_digest" \
  '{schema_version: 1, image: "ghcr.io/telecrypt-io/controlplane", tag: "test", source_commit: ("a" * 40), annotated_tag_sha: ("b" * 40), digest: $digest}' >"$temporary/binding.json"
binding_asset_digest="sha256:$(sha256sum "$temporary/binding.json" | awk '{print $1}')"
test "$binding_asset_digest" != "$binding_image_digest"
binding_filter='type == "object" and .schema_version == 1 and (.digest | type == "string" and test("^sha256:[0-9a-f]{64}$")) and .digest == $image_digest'
jq -e --arg image_digest "$binding_image_digest" "$binding_filter" "$temporary/binding.json" >/dev/null
if jq -e --arg image_digest "$binding_asset_digest" "$binding_filter" "$temporary/binding.json" >/dev/null; then
  echo 'binding asset digest was incorrectly accepted as the image digest' >&2
  exit 1
fi

asset_shape_filter='all(.assets[];
  (.id | type == "number" and . > 0 and . == floor) and
  (.size | type == "number" and . > 0 and . <= 67108864) and
  (.digest | type == "string" and test("^sha256:[0-9a-f]{64}$")))'
jq -cn --arg digest "$test_digest" '{assets: [{id: 7, size: 1, digest: $digest}]}' >"$temporary/release-assets-valid.json"
jq -e "$asset_shape_filter" "$temporary/release-assets-valid.json" >/dev/null
for hostile_id in 7.5 '{}'; do
  jq -cn --argjson id "$hostile_id" --arg digest "$test_digest" \
    '{assets: [{id: $id, size: 1, digest: $digest}]}' >"$temporary/release-assets-hostile.json"
  if jq -e "$asset_shape_filter" "$temporary/release-assets-hostile.json" >/dev/null; then
    echo "hostile Release asset ID was accepted: $hostile_id" >&2
    exit 1
  fi
done

printf '%s' "[{\"id\":7,\"name\":\"$test_digest\",\"metadata\":{\"package_type\":\"container\",\"container\":{\"tags\":[]}}}]" >"$temporary/ghcr-valid.json"
test "$(ghcr_version_records "$temporary/ghcr-valid.json" "$project_version" "$test_digest")" = $'7\tsha256:0000000000000000000000000000000000000000000000000000000000000000\t0\t1'
printf '%s' "[{\"id\":1,\"name\":\"$test_digest\",\"metadata\":{\"package_type\":\"container\",\"container\":{\"tags\":[\"hostile-tag\",\"hostile-tag\"]}}}]" >"$temporary/ghcr-duplicate-tags.json"
if ghcr_version_records "$temporary/ghcr-duplicate-tags.json" hostile-tag "$test_digest" >/dev/null; then
  echo 'GHCR response with duplicate tags was accepted' >&2
  exit 1
fi
printf '%s' "[{\"id\":\"1\",\"name\":\"$test_digest\",\"metadata\":{\"package_type\":\"container\",\"container\":{\"tags\":[]}}}]" >"$temporary/ghcr-invalid-shape.json"
if ghcr_version_records "$temporary/ghcr-invalid-shape.json" "$project_version" "$test_digest" >/dev/null; then
  echo 'GHCR response with nonnumeric ID was accepted' >&2
  exit 1
fi

set +e
(
  cd "$temporary"
  source "$repo_root/scripts/release-helpers.sh"
  capture_command "$temporary/stdout" 120 /usr/bin/python3 -c \
    'from pathlib import Path; Path("work.bin").write_bytes(b"x" * 131072); print("ok")'
)
status=$?
set -e
test "$status" -eq 0
test "$(cat "$temporary/stdout")" = ok
test "$(stat -c %s "$temporary/work.bin")" -eq 131072

set +e
(
  source "$repo_root/scripts/release-helpers.sh"
  capture_command "$temporary/failure-stdout" 120 /usr/bin/python3 -c \
    'import sys; print("partial"); print("failure", file=sys.stderr); raise SystemExit(17)'
)
status=$?
set -e
test "$status" -eq 17
test "$(cat "$temporary/failure-stdout")" = partial
test "$(cat "$temporary/failure-stdout.stderr")" = failure

set +e
(
  source "$repo_root/scripts/release-helpers.sh"
  capture_command "$temporary/success-stderr" 120 /usr/bin/python3 -c \
    'import sys; print("ok"); print("warning", file=sys.stderr)'
)
status=$?
set -e
test "$status" -eq 0
test "$(cat "$temporary/success-stderr")" = ok
test "$(grep -Fc warning "$temporary/success-stderr.stderr")" -eq 1

set +e
(
  source "$repo_root/scripts/release-helpers.sh"
  capture_command "$temporary/large-stderr" 120 /usr/bin/python3 -c \
    'import sys; sys.stderr.write("x" * 70000)'
)
status=$?
set -e
test "$status" -eq 0
test ! -s "$temporary/large-stderr"
test "$(stat -c %s "$temporary/large-stderr.stderr")" -eq 70000

# shellcheck source=scripts/check-release-source_helpers.sh
source "$url_helper"
canonical_repository='TeleCrypt-io/control-plane'
canonical_url='https://github.com/TeleCrypt-io/control-plane.git'
test "$(normalize_canonical_origin_url "$canonical_repository" 'https://github.com/TeleCrypt-io/control-plane')" = "$canonical_url"
test "$(normalize_canonical_origin_url "$canonical_repository" "$canonical_url")" = "$canonical_url"

for hostile_url in \
  'https://user:secret@github.com/TeleCrypt-io/control-plane.git' \
  'http://github.com/TeleCrypt-io/control-plane.git' \
  'https://gitlab.com/TeleCrypt-io/control-plane.git' \
  'https://github.com/TeleCrypt-io/control-plane/' \
  'https://github.com/TeleCrypt-io/control-plane.git?query=1' \
  'ssh://git@github.com/TeleCrypt-io/control-plane.git' \
  $'https://github.com/TeleCrypt-io/control-plane\nhttps://github.com/TeleCrypt-io/control-plane.git'; do
  if normalize_canonical_origin_url "$canonical_repository" "$hostile_url" >/dev/null; then
    echo "hostile origin URL was accepted: $hostile_url" >&2
    exit 1
  fi
done

if normalize_canonical_origin_url "$canonical_repository" '' >/dev/null; then
  echo 'empty origin URL was accepted' >&2
  exit 1
fi
