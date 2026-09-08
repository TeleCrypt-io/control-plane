#!/usr/bin/env bash
set -euo pipefail

: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
: "${RELEASE_TAG:?RELEASE_TAG is required}"
: "${RELEASE_SHA:?RELEASE_SHA is required}"

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
# The checkout action's canonical HTTPS origin may omit .git.  Normalize only those
# two spellings before requiring both origin URL lists to resolve to one repository.
# The later fetch deliberately uses repo_url so it remains public and anonymous.
# shellcheck source=scripts/check-release-source_helpers.sh
source "$script_dir/check-release-source_helpers.sh"

[[ "$GITHUB_REPOSITORY" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || {
  echo 'GITHUB_REPOSITORY is not canonical' >&2
  exit 2
}
[[ "$RELEASE_TAG" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || {
  echo 'release tag is not canonical X.Y.Z' >&2
  exit 2
}
[[ "$RELEASE_SHA" =~ ^[0-9a-f]{40}$ ]] || {
  echo 'RELEASE_SHA is not a canonical commit ID' >&2
  exit 2
}

readonly repo_url="https://github.com/${GITHUB_REPOSITORY}.git"
readonly tag_ref="refs/tags/$RELEASE_TAG"
readonly remote_tag_ref='refs/remotes/origin/release-tag'
readonly remote_main_ref='refs/remotes/origin/main'
# Keep Git independent of runner configuration and credentials.  The command uses the
# canonical HTTPS URL below, so local remotes cannot redirect the source fetch.
git=(
  /usr/bin/env -i PATH=/usr/bin:/bin
  GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
  GIT_TERMINAL_PROMPT=0 GIT_NO_REPLACE_OBJECTS=1
  /usr/bin/git
  -c credential.helper=
  -c 'credential.https://github.com.helper='
  -c http.proxy= -c 'http.https://github.com.proxy='
  -c http.extraHeader= -c 'http.https://github.com/.extraheader='
  -c core.sshCommand=false
)

git_command() {
  local status
  set +e
  timeout --signal=TERM --kill-after=5s 30s "${git[@]}" "$@"
  status=$?
  set -e
  return "$status"
}

die() { echo "$1" >&2; exit 1; }

remote_fetch_urls="$(git_command remote get-url --all origin)" || die 'could not read the origin fetch URL'
remote_push_urls="$(git_command remote get-url --all --push origin)" || die 'could not read the origin push URL'
normalized_fetch_url="$(normalize_canonical_origin_url "$GITHUB_REPOSITORY" "$remote_fetch_urls")" ||
  die 'origin fetch URL is not exactly one canonical HTTPS repository URL'
normalized_push_url="$(normalize_canonical_origin_url "$GITHUB_REPOSITORY" "$remote_push_urls")" ||
  die 'origin push URL is not exactly one canonical HTTPS repository URL'
[[ "$normalized_fetch_url" == "$repo_url" && "$normalized_push_url" == "$repo_url" ]] ||
  die 'origin fetch and push URLs do not resolve to the canonical repository'

checkout_tag_type="$(git_command cat-file -t "$tag_ref")" || die 'checked-out release tag cannot be read'
[[ "$checkout_tag_type" == tag ]] || die 'release tag is not annotated'
checkout_tag_sha="$(git_command rev-parse --verify --end-of-options "$tag_ref")" || die 'checked-out tag object cannot be read'
checkout_commit="$(git_command rev-parse --verify --end-of-options HEAD)" || die 'checked-out commit cannot be read'
checkout_peeled="$(git_command rev-parse --verify --end-of-options "$tag_ref^{}")" || die 'checked-out tag target cannot be read'
[[ "$checkout_tag_sha" =~ ^[0-9a-f]{40}$ && "$checkout_peeled" == "$RELEASE_SHA" && "$checkout_commit" == "$RELEASE_SHA" ]] ||
  die 'checked-out tag, peeled commit, HEAD, and RELEASE_SHA do not match'

git_command fetch --force --no-tags "$repo_url" \
  "refs/tags/$RELEASE_TAG:$remote_tag_ref" refs/heads/main:"$remote_main_ref" ||
  die 'release source fetch failed or exceeded its timeout'

remote_tag_type="$(git_command cat-file -t "$remote_tag_ref")" || die 'fetched release tag cannot be read'
remote_tag_sha="$(git_command rev-parse --verify --end-of-options "$remote_tag_ref")" || die 'fetched tag object cannot be read'
remote_peeled="$(git_command rev-parse --verify --end-of-options "$remote_tag_ref^{}")" || die 'fetched tag target cannot be read'
[[ "$remote_tag_type" == tag && "$remote_tag_sha" == "$checkout_tag_sha" && "$remote_peeled" == "$RELEASE_SHA" ]] ||
  die 'remote tag object or peeled commit does not match the checked-out source'

git_command merge-base --is-ancestor "$RELEASE_SHA" "$remote_main_ref" >/dev/null ||
  die 'release commit is not contained in refreshed main'

if [[ -n "${GITHUB_ENV:-}" ]]; then
  printf 'ANNOTATED_TAG_SHA=%s\n' "$checkout_tag_sha" >>"$GITHUB_ENV"
fi
