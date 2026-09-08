#!/usr/bin/env bash
# shellcheck disable=SC2016
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
helper="$repo_root/scripts/check-release-source.sh"
url_helper="$repo_root/scripts/check-release-source_helpers.sh"
workflow="$repo_root/.github/workflows/build.yml"
tier_controller_pyproject="$repo_root/synapse/tier_controller/pyproject.toml"
image_contract_helper="$repo_root/scripts/validate-image-contract.sh"

grep -Fqx '#!/usr/bin/env bash' "$helper"
grep -Fqx '#!/usr/bin/env bash' "$url_helper"
grep -Fq 'actions/checkout@v7.0.1' "$workflow"
grep -Fq 'fetch-depth: 0' "$workflow"
grep -Fq 'persist-credentials: false' "$workflow"
grep -Fq 'GIT_NO_REPLACE_OBJECTS=1' "$helper"
grep -Fq 'GIT_CONFIG_GLOBAL=/dev/null' "$helper"
grep -Fq 'GIT_CONFIG_SYSTEM=/dev/null' "$helper"
grep -Fq 'credential.helper=' "$helper"
grep -Fq 'http.proxy=' "$helper"
grep -Fq 'https://github.com/${GITHUB_REPOSITORY}.git' "$helper"
grep -Fq 'remote get-url --all origin' "$helper"
grep -Fq 'remote get-url --all --push origin' "$helper"
grep -Fq 'normalize_canonical_origin_url' "$helper"
grep -Fq 'refs/tags/$RELEASE_TAG:$remote_tag_ref' "$helper"
grep -Fq 'refs/heads/main:"$remote_main_ref"' "$helper"
grep -Fq 'merge-base --is-ancestor' "$helper"
grep -Fq 'capture_command' "$repo_root/scripts/release-helpers.sh"
grep -Fq 'capture_value' "$image_contract_helper"
grep -Fq 'cat -- "$output" >&2' "$image_contract_helper"
grep -Fq 'cat -- "$stderr_file" >&2' "$image_contract_helper"
if grep -Fq 'fetch --quiet' "$helper"; then
  echo 'private repository source proof must retain complete Git fetch diagnostics' >&2
  exit 1
fi
if grep -Eq '2>&1[[:space:]]*\|[[:space:]]*/usr/bin/head' "$repo_root/scripts/check-release-source.sh"; then
  echo 'Git output must remain complete on stdout and stderr' >&2
  exit 1
fi
grep -Fq -- '--draft' "$workflow"
grep -Fq -- '--method PATCH' "$workflow"
grep -Fq 'scripts/check-release-source.sh' "$workflow"
grep -Fq 'RELEASE_IMAGE_DIGEST' "$workflow"
grep -Fq -- '--arg image_digest "$RELEASE_IMAGE_DIGEST"' "$workflow"
grep -Fq '.digest == $image_digest' "$workflow"
if grep -Fq -- '--arg digest "$(jq -er --arg name "$RELEASE_BINDING"' "$workflow"; then
  echo 'binding image digest must not be compared with the Release asset file digest' >&2
  exit 1
fi
grep -Fq 'RELEASE_BINDING' "$workflow"
grep -Fq 'RELEASE_WHEEL' "$workflow"
grep -Fq 'source_commit' "$workflow"
grep -Fq 'annotated_tag_sha' "$workflow"
grep -Fq 'org.telecrypt.controlplane.release=${{ env.RELEASE_TAG }}' "$workflow"
grep -Fq 'org.telecrypt.tier-controller.release=${{ env.RELEASE_TAG }}' "$workflow"
grep -Fq "'{schema_version: 1, image: \$image, tag: \$tag, source_commit: \$source_commit, annotated_tag_sha: \$annotated_tag_sha, digest: \$digest}'" "$workflow"
grep -Fq '(.assets | type == "array" and length == 2' "$workflow"
grep -Fq 'and .immutable == true' "$workflow"
if grep -Eqi '(release[_ -](tag|version)|RELEASE_(TAG|WHEEL|BINDING)).*[0-9]+\.[0-9]+\.[0-9]+' "$workflow"; then
  echo 'release workflow must derive the release version from the exact tag' >&2
  exit 1
fi
if grep -Eq 'attest-build-provenance@|^[[:space:]]+(attestations|id-token|artifact-metadata):' "$workflow"; then
  echo 'release workflow must not request attestation or related token authority' >&2
  exit 1
fi
grep -Fq 'releases?per_page=100&page=' "$workflow"
grep -Fq "select(.draft == true and .tag_name == \$tag)" "$workflow"
grep -Fq "releases/\$RELEASE_DRAFT_ID" "$workflow"
grep -Fq "releases/\$RELEASE_ID" "$workflow"
grep -Fq 'name: controlplane-wheel-${{ github.run_id }}-${{ github.sha }}' "$workflow"
grep -Fq 'github_expression_prefix=' "$workflow"
grep -Fq 'expected_wheel_name=' "$workflow"
grep -Fq 'wheel_name = pathlib.Path(sys.argv[1]).name' "$workflow"
grep -Fq "wheel_version = wheel_name.removeprefix(wheel_prefix).split('-', 1)[0]" "$workflow"
if grep -Fq "sys.argv[1].split('-')[1]" "$workflow"; then
  echo 'wheel version validation must parse the wheel basename' >&2
  exit 1
fi
grep -Fq -- '--env MAS_OIDC_CLIENT_ID=01J00000000000000000000000' "$workflow"
if grep -Eq -- '--env MAS_OIDC_CLIENT_ID=01J00000000000000000000([[:space:]]|")' "$workflow"; then
  echo 'smoke Plan client ID must satisfy the canonical 26-character contract' >&2
  exit 1
fi
grep -Fq 'emit_container_diagnostics' "$workflow"
grep -Fq 'docker inspect --format' "$workflow"
grep -Fq 'docker logs' "$workflow"
grep -Fq 'redact_diagnostics' "$workflow"
grep -Fq 'type=docker,name=${{ env.IMAGE_BUILD_REF }},dest=${{ runner.temp }}/controlplane-image.tar' "$workflow"
grep -Fq 'type=image,name=${{ env.IMAGE }},push=true,push-by-digest=true,name-canonical=true' "$workflow"
if grep -Fq 'type=registry,name=${{ env.IMAGE_BUILD_REF }},push=true' "$workflow" || grep -Fq 'tags: ${{ env.IMAGE_BUILD_REF }}' "$workflow"; then
  echo 'staging image must not leave a mutable registry tag' >&2
  exit 1
fi
grep -Fq 'buildx imagetools inspect "$IMAGE@$BUILD_DIGEST"' "$workflow"
grep -Fq 'GH_TOKEN: ${{ github.token }}' "$workflow"
grep -Fq 'orgs/$package_owner/packages/container/$package_name/versions?per_page=100&page=' "$workflow"
grep -Fq 'ghcr_version_records' "$workflow"
grep -Fq 'declare -A package_ids=() package_digests=()' "$workflow"
grep -Fq 'GHCR package version pagination returned a duplicate ID or digest' "$workflow"
grep -Fq 'GHCR package version response failed strict schema validation' "$workflow"
if grep -Fq -- "--jq '[.[] | {id,name,metadata}]'" "$workflow"; then
  echo 'GHCR API response diagnostics must not be filtered before retention' >&2
  exit 1
fi
grep -Fq 'for (( page=1; ; page++ )); do' "$workflow"
grep -Fq 'smoke diagnostic child wait failed during %s (status %s)' "$workflow"
grep -Fq 'image contract child wait failed during %s (status %s)' "$repo_root/scripts/validate-image-contract.sh"
if grep -Eq '\[\[ "\$page" -lt 100 \]\]|for page in \$\(seq 1 100\); do|reached its bound' "$workflow"; then
  echo 'Release and package discovery must rely on pagination completion and workflow deadlines, not a total page ceiling' >&2
  exit 1
fi
grep -Fq 'for attempt in $(seq 1 5); do' "$workflow"
grep -Fq '[[ "$attempt" -lt 5 ]] && sleep 2' "$workflow"
grep -Fq '(.id | type == "number" and . > 0 and . == floor)' "$workflow"
if grep -Fq '(.id | type) == "number" and .id > 0 and .id == floor' "$workflow"; then
  echo 'Release asset IDs must be validated while the jq input is the numeric ID' >&2
  exit 1
fi
if grep -Fq 'inspection="$(docker_command buildx imagetools inspect "$IMAGE:$RELEASE_TAG"' "$workflow"; then
  echo 'immutable image-tag absence must use the authenticated Packages API, not human Docker text' >&2
  exit 1
fi
PYTHONDONTWRITEBYTECODE=1 python3 - "$workflow" <<'PY'
import pathlib
import re
import sys

lines = pathlib.Path(sys.argv[1]).read_text().splitlines()
blocks = []
block = []
for line in lines:
    if re.match(r'^      - ', line):
        if block:
            blocks.append(block)
        block = [line]
    elif block:
        block.append(line)
if block:
    blocks.append(block)

for block in blocks:
    invocations = [
        index for index, line in enumerate(block)
        if 'docker_command' in line and not re.search(r'docker_command\s*\(\)\s*\{', line)
    ]
    if not invocations:
        continue
    definitions = [
        index for index, line in enumerate(block)
        if re.search(r'docker_command\s*\(\)\s*\{', line)
    ]
    assert definitions and min(definitions) < min(invocations), block[0]

    deadline_invocations = [
        index for index, line in enumerate(block)
        if 'capture_command ' in line and 'grep' not in line
    ]
    if deadline_invocations:
        helper_sources = [
            index for index, line in enumerate(block)
            if line.strip() == 'source scripts/release-helpers.sh'
        ]
        assert helper_sources and min(helper_sources) < min(deadline_invocations), block[0]

create = next(index for index, line in enumerate(lines) if 'buildx imagetools create --prefer-index=false' in line)
final = next(index for index, line in enumerate(lines) if 'final_digest="$(docker_command buildx imagetools inspect "$IMAGE:$RELEASE_TAG"' in line)
assert create < final
PY
if grep -Fq -- '--detach --rm --name "$registration_name"' "$workflow" || grep -Fq -- '--detach --rm --name "$plan_name"' "$workflow"; then
  echo 'failed smoke containers must remain available for diagnostics until cleanup' >&2
  exit 1
fi
if grep -Fq -- '--silent' "$workflow" || grep -Fq -- '--output /dev/null' "$workflow"; then
  echo 'readiness retries must retain curl transport and response diagnostics' >&2
  exit 1
fi
grep -Fq -- '--no-progress-meter --show-error' "$workflow"
grep -Fq 'registration_curl_status=$?' "$workflow"
grep -Fq 'plan_curl_status=$?' "$workflow"
PYTHONDONTWRITEBYTECODE=1 python3 - "$tier_controller_pyproject" <<'PY'
import pathlib
import sys
import tomllib

pyproject = pathlib.Path(sys.argv[1])
project_version = tomllib.loads(pyproject.read_text())['project']['version']
wheel_path = pathlib.Path(
    '/tmp/tier-controller/'
    f'telecrypt_tier_controller-{project_version}-py3-none-any.whl'
)
wheel_name = wheel_path.name
wheel_prefix = 'telecrypt_tier_controller-'
assert wheel_name.startswith(wheel_prefix)
wheel_version = wheel_name.removeprefix(wheel_prefix).split('-', 1)[0]
assert wheel_version == project_version
PY
legacy_edit="$(printf '%s %s' gh 'release edit')"
tag_release_path="$(printf '%s/%s/' releases tags)"
if grep -Fq "$legacy_edit" "$workflow" || grep -Fq "$tag_release_path" "$workflow"; then
  echo 'draft Release path must use paginated discovery and numeric release IDs' >&2
  exit 1
fi
grep -Fq 'cat-file -t' "$helper"
grep -Fq 'tag_ref^{}' "$helper"
grep -Fq 'checkout_commit" == "$RELEASE_SHA"' "$helper"
grep -Fq 'ANNOTATED_TAG_SHA=' "$helper"
grep -Fq 'timeout --signal=TERM --kill-after=5s 120s docker pull "$SYNAPSE_IMAGE"' "$workflow"
grep -Fq 'timeout --signal=TERM --kill-after=5s 120s docker run --rm --user 0:0' "$workflow"
if grep -Eq 'bounded-command|stdout-limit|stderr-limit|process\.poll\(' "$workflow" "$helper" "$repo_root/scripts/release-helpers.sh"; then
  echo 'release command capture must not impose diagnostic output limits or custom process polling' >&2
  exit 1
fi
grep -Fq 'license-files = ["LICENSE", "NOTICE"]' "$tier_controller_pyproject"
if grep -Fq 'license-files = ["../../LICENSE", "../../NOTICE"]' "$tier_controller_pyproject"; then
  echo 'tier-controller license metadata must use project-local files' >&2
  exit 1
fi
cmp -s "$repo_root/LICENSE" "$repo_root/synapse/tier_controller/LICENSE"
cmp -s "$repo_root/NOTICE" "$repo_root/synapse/tier_controller/NOTICE"

if grep -Eq 'GIT_CONFIG_KEY_|GIT_INDEX_FILE|config --(local|worktree)|symlink' "$helper"; then
  echo 'source helper contains retired hostile Git machinery' >&2
  exit 1
fi
if grep -Eq 'created_at|published_at|browser_download_url|expected_release_url' "$workflow"; then
  echo 'workflow contains retired derived Release assertions' >&2
  exit 1
fi

temporary="$(mktemp -d)"
trap 'rm -rf -- "$temporary"' EXIT
source "$repo_root/scripts/release-helpers.sh"
project_version="$(sed -n 's/^version = "\([^"]*\)"$/\1/p' "$tier_controller_pyproject")"
test -n "$project_version"
printf '%s\n' \
  'MAS_OIDC_CLIENT_SECRET=fake-secret' \
  'PLAN_SESSION_KEY: fake-token' \
  'private key=fake-private-key' >"$temporary/diagnostic"
test "$(redact_diagnostics "$temporary/diagnostic")" = $'MAS_OIDC_CLIENT_SECRET=[redacted]\nPLAN_SESSION_KEY: [redacted]\nprivate key=[redacted]'
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
  # The child writes a legitimate work file while its complete output is captured.
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
canonical_repository='TeleCrypt-io/controlplane'
canonical_url='https://github.com/TeleCrypt-io/controlplane.git'
test "$(normalize_canonical_origin_url "$canonical_repository" 'https://github.com/TeleCrypt-io/controlplane')" = "$canonical_url"
test "$(normalize_canonical_origin_url "$canonical_repository" "$canonical_url")" = "$canonical_url"

for hostile_url in \
  'https://user:secret@github.com/TeleCrypt-io/controlplane.git' \
  'http://github.com/TeleCrypt-io/controlplane.git' \
  'https://gitlab.com/TeleCrypt-io/controlplane.git' \
  'https://github.com/TeleCrypt-io/controlplane/' \
  'https://github.com/TeleCrypt-io/controlplane.git?query=1' \
  'ssh://git@github.com/TeleCrypt-io/controlplane.git' \
  $'https://github.com/TeleCrypt-io/controlplane\nhttps://github.com/TeleCrypt-io/controlplane.git'; do
  if normalize_canonical_origin_url "$canonical_repository" "$hostile_url" >/dev/null; then
    echo "hostile origin URL was accepted: $hostile_url" >&2
    exit 1
  fi
done

if normalize_canonical_origin_url "$canonical_repository" '' >/dev/null; then
  echo 'empty origin URL was accepted' >&2
  exit 1
fi
