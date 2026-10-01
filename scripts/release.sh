#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
if [[ $# != 1 ]]; then echo "Usage: scripts/release.sh X.Y.Z" >&2; exit 2; fi
RELEASE_TAG="$1"
RELEASE_SHA="$(git rev-parse HEAD)"
export RELEASE_TAG RELEASE_SHA
[[ "$RELEASE_TAG" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]
[[ "$(git cat-file -t "$RELEASE_TAG")" == tag ]]
[[ "$(git rev-parse "$RELEASE_TAG^{commit}")" == "$RELEASE_SHA" ]]
test -z "$(git status --porcelain)"
export GITHUB_REPOSITORY=TeleCrypt-io/control-plane
release_dir="$(mktemp -d)"
export TMPDIR="$release_dir"
trap 'rm -rf -- "$release_dir"' EXIT
GH_TOKEN="${GH_TOKEN:-$(gh auth token)}"
export GH_TOKEN
scripts/check.sh
IMAGE="ghcr.io/telecrypt-io/controlplane"
RELEASE_WHEEL="telecrypt_tier_controller-${RELEASE_TAG}-py3-none-any.whl"
RELEASE_BINDING="controlplane-${RELEASE_TAG}.digest.json"
ANNOTATED_TAG_SHA="$(git rev-parse "$RELEASE_TAG^{tag}")"

# Verify wheel and source version
source_version="$(python3 -c 'import tomllib; print(tomllib.load(open("pyproject.toml", "rb"))["project"]["version"])')"
[[ "$source_version" == "$RELEASE_TAG" ]]
shopt -s nullglob
wheels=(dist/tier-controller/*.whl)
[[ "${#wheels[@]}" -eq 1 ]]
wheel="${wheels[0]##*/}"
[[ "$wheel" == "$RELEASE_WHEEL" ]]
(cd dist/tier-controller && sha256sum --strict --check "$wheel.sha256")
python3 - "${wheels[0]}" <<'PY'
import email, pathlib, sys, zipfile
with zipfile.ZipFile(sys.argv[1]) as archive:
    names = set(archive.namelist())
    metadata_name = next(n for n in names if n.endswith('.dist-info/METADATA'))
    metadata = email.message_from_bytes(archive.read(metadata_name))
    assert metadata['Name'] == 'telecrypt-tier-controller'
    assert not metadata.get_all('Requires-Dist')
    assert any(n.endswith('.dist-info/licenses/LICENSE') for n in names)
    assert any(n.endswith('.dist-info/licenses/NOTICE') for n in names)
    assert metadata['Version'] == pathlib.Path(sys.argv[1]).name.removeprefix('telecrypt_tier_controller-').split('-', 1)[0]
PY
for notice in LICENSE NOTICE; do test -s "$notice"; done


# Log in to GHCR
printf '%s' "$GH_TOKEN" | docker login ghcr.io --username "$(gh api user --jq .login)" --password-stdin

# Build and push image
docker buildx build --platform linux/amd64 --provenance=false --metadata-file "$release_dir/build.json" --target controlplane --push --tag "$IMAGE:$RELEASE_TAG" \
  --label "org.opencontainers.image.source=https://github.com/${GITHUB_REPOSITORY}" \
  --label "org.opencontainers.image.revision=${RELEASE_SHA}" \
  --label "org.opencontainers.image.version=${RELEASE_TAG}" \
  --label "org.opencontainers.image.licenses=BUSL-1.1" \
  --label "org.opencontainers.image.title=TeleCrypt Controlplane" \
  --label "org.opencontainers.image.description=TeleCrypt Registration, Janitor, and Plan services" \
  --label "org.opencontainers.image.vendor=TeleCrypt.io" \
  --label "io.telecrypt.config-contract=1" \
  --label "org.telecrypt.controlplane.release=${RELEASE_TAG}" \
  --label "org.telecrypt.tier-controller.release=${RELEASE_TAG}" .
BUILD_DIGEST="$(jq -er '."containerimage.digest" | select(test("^sha256:[0-9a-f]{64}$"))' "$release_dir/build.json")"

# Smoke-test published image
(
IMAGE_REF="${IMAGE}:${RELEASE_TAG}"
[[ "$BUILD_DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]]
docker pull "$IMAGE_REF"
for expected in \
  "org.opencontainers.image.source=https://github.com/$GITHUB_REPOSITORY" \
  "org.opencontainers.image.revision=$RELEASE_SHA" \
  "org.opencontainers.image.version=$RELEASE_TAG" \
  "org.opencontainers.image.licenses=BUSL-1.1" \
  "org.opencontainers.image.title=TeleCrypt Controlplane" \
  "org.opencontainers.image.description=TeleCrypt Registration, Janitor, and Plan services" \
  "org.opencontainers.image.vendor=TeleCrypt.io" \
  "io.telecrypt.config-contract=1" \
  "org.telecrypt.controlplane.release=$RELEASE_TAG" \
  "org.telecrypt.tier-controller.release=$RELEASE_TAG"; do
  key="${expected%%=*}"
  value="${expected#*=}"
  [[ "$(docker image inspect --format "{{index .Config.Labels \"$key\"}}" "$IMAGE_REF")" == "$value" ]]
done
[[ "$(docker image inspect --format '{{.Config.User}}' "$IMAGE_REF")" == "991:991" ]]
[[ "$(docker image inspect --format '{{json .Config.Entrypoint}}' "$IMAGE_REF")" == "null" ]]
[[ "$(docker image inspect --format '{{json .Config.Cmd}}' "$IMAGE_REF")" == '["/registration"]' ]]
published_digest="$(docker buildx imagetools inspect "$IMAGE_REF" --format '{{.Manifest.Digest}}')"
[[ "$published_digest" == "$BUILD_DIGEST" ]]
registration_name=controlplane-registration-smoke
plan_name=controlplane-plan-smoke
cleanup() { docker rm -f "$registration_name" "$plan_name" >/dev/null 2>&1 || true; }
trap cleanup EXIT
docker run --detach --network host --name "$registration_name" \
  --env SERVER_NAME=example.invalid "$IMAGE_REF" /registration
docker run --detach --network host --name "$plan_name" \
--env SERVER_NAME=example.invalid --env BILLING_ENVIRONMENT=test \
--env MAS_OIDC_CLIENT_ID=01J00000000000000000000000 \
--env MAS_OIDC_CLIENT_SECRET=smoke-secret \
--env PLAN_SESSION_KEY=ssssssssssssssssssssssssssssssss \
--env CASHIER_PLAN_TOKEN=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
--env PLAN_BILLING_LINK_1=https://checkout.example.invalid/tier-1 \
--env PLAN_BILLING_LINK_2=https://checkout.example.invalid/tier-2 \
--env PLAN_BILLING_LINK_3=https://checkout.example.invalid/tier-3 \
--env PLAN_BILLING_LINK_4=https://checkout.example.invalid/tier-4 \
--env PLAN_BILLING_PORTAL_URL=https://portal.example.invalid/login \
"$IMAGE_REF" /plan
wait_for_status() {
  local url="$1" expected="$2" status
  for _ in $(seq 1 30); do
    status="$(curl --no-progress-meter --connect-timeout 1 --max-time 3 --output /dev/null --write-out '%{http_code}' "$url" 2>/dev/null || true)"
    [[ "$status" == "$expected" ]] && return 0
    sleep 1
  done
  return 1
}
if ! wait_for_status http://127.0.0.1:9009/redpill 405; then
  docker logs "$registration_name" || true
  exit 1
fi
if ! wait_for_status http://127.0.0.1:9012/plan/overview 200; then
  docker logs "$plan_name" || true
  exit 1
fi

)

# Create release assets
IMAGE_DIGEST="${BUILD_DIGEST}"
[[ "$IMAGE_DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]]
jq -cS -n \
  --arg image "$IMAGE" --arg tag "$RELEASE_TAG" --arg source "$RELEASE_SHA" \
  --arg tag_object "$ANNOTATED_TAG_SHA" --arg digest "$IMAGE_DIGEST" \
  '{schema_version: 1, image: $image, tag: $tag, source_commit: $source, annotated_tag_sha: $tag_object, digest: $digest}' \
  >"$release_dir/$RELEASE_BINDING"
gh release create "$RELEASE_TAG" \
  "dist/tier-controller/$RELEASE_WHEEL" "$release_dir/$RELEASE_BINDING" \
  --repo "$GITHUB_REPOSITORY" --verify-tag --title "$RELEASE_TAG" \
  --notes "Exact Controlplane release $RELEASE_TAG."
mapfile -t assets < <(gh release view "$RELEASE_TAG" --repo "$GITHUB_REPOSITORY" --json assets --jq '.assets[].name' | sort)
[[ "${#assets[@]}" -eq 2 ]]
[[ "${assets[0]}" == "$RELEASE_BINDING" ]]
[[ "${assets[1]}" == "$RELEASE_WHEEL" ]]

