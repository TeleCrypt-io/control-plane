#!/usr/bin/env bash
set -euo pipefail

: "${IMAGE_REF:?IMAGE_REF is required}"
: "${RELEASE_TAG:?RELEASE_TAG is required}"
: "${RELEASE_SHA:?RELEASE_SHA is required}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"

temporary_root="$(mktemp -d "${TMPDIR:-/tmp}/controlplane-image.XXXXXX")"
active_pid=""
active_output=""
active_stderr=""

cleanup() {
  local status=0
  if ! rm -rf -- "$temporary_root"; then
    status=1
  fi
  return "$status"
}

cleanup_on_exit() {
  local status=$?
  trap - EXIT HUP INT TERM
  if ! cleanup; then
    echo 'image contract temporary-directory cleanup failed' >&2
    if [[ "$status" -eq 0 ]]; then
      status=1
    fi
  fi
  exit "$status"
}

signal_exit() {
  local signal_name="$1" status=143 probe_status=0 kill_status=0 wait_status replay_status=0 failure_status=0
  case "$signal_name" in
    HUP) status=129 ;;
    INT) status=130 ;;
    TERM) status=143 ;;
    *) status=143 ;;
  esac
  set +e
  if [[ -n "$active_pid" ]]; then
    kill -0 "$active_pid"
    probe_status=$?
    if [[ "$probe_status" -eq 0 ]]; then
      kill -TERM "$active_pid"
      kill_status=$?
      if [[ "$kill_status" -ne 0 ]]; then
        printf 'image contract child termination failed during %s (status %s)\n' "$signal_name" "$kill_status" >&2
        failure_status=1
      fi
    elif [[ "$probe_status" -ne 1 ]]; then
      printf 'image contract child liveness check failed during %s (status %s)\n' "$signal_name" "$probe_status" >&2
      failure_status=1
    fi
    wait "$active_pid"
    wait_status=$?
    active_pid=""
    if [[ "$wait_status" -ne 0 && "$wait_status" -ne 143 ]]; then
      printf 'image contract child wait failed during %s (status %s)\n' "$signal_name" "$wait_status" >&2
      failure_status=1
    fi
    if [[ "$wait_status" -eq 0 ]]; then
      printf 'image contract child exited successfully while handling %s\n' "$signal_name" >&2
    fi
  fi
  if [[ -n "$active_output" ]] && ! cat -- "$active_output" >&2; then
    replay_status=1
  fi
  if [[ -n "$active_stderr" ]] && ! cat -- "$active_stderr" >&2; then
    replay_status=1
  fi
  if (( replay_status != 0 )); then
    echo 'image contract diagnostics could not be replayed after signal' >&2
    failure_status=1
  fi
  if (( failure_status != 0 )); then status=1; fi
  exit "$status"
}

trap cleanup_on_exit EXIT
trap 'signal_exit HUP' HUP
trap 'signal_exit INT' INT
trap 'signal_exit TERM' TERM

capture_value() {
  local output stderr_file status cleanup_status=0 replay_status=0
  output="$(mktemp "$temporary_root/output.XXXXXX")"
  stderr_file="$output.stderr"
  active_output="$output"
  active_stderr="$stderr_file"
  set +e
  timeout --signal=TERM --kill-after=5s 120s docker "$@" >"$output" 2>"$stderr_file" &
  active_pid="$!"
  wait "$active_pid"
  status="$?"
  set -e
  active_pid=""
  if (( status != 0 )); then
    if ! cat -- "$output" >&2; then
      replay_status=1
    fi
    if ! cat -- "$stderr_file" >&2; then
      replay_status=1
    fi
    if (( replay_status != 0 )); then
      echo 'image contract diagnostics could not be replayed' >&2
    fi
    if ! rm -f -- "$output" "$stderr_file"; then
      cleanup_status=1
    fi
    active_output=""
    active_stderr=""
    if (( cleanup_status != 0 )); then
      echo 'image contract command-output cleanup failed' >&2
    fi
    return "$status"
  fi
  if ! cat -- "$stderr_file" >&2; then
    cleanup_status=1
  fi
  if ! cat -- "$output"; then
    cleanup_status=1
  fi
  if ! rm -f -- "$output" "$stderr_file"; then
    cleanup_status=1
  fi
  active_output=""
  active_stderr=""
  if (( cleanup_status != 0 )); then
    echo 'image contract command-output cleanup or emission failed' >&2
    return 1
  fi
  return 0
}

expected_source="https://github.com/${GITHUB_REPOSITORY}"
for label_expectation in \
  "org.opencontainers.image.source=$expected_source" \
  "org.opencontainers.image.revision=$RELEASE_SHA" \
  "org.opencontainers.image.version=$RELEASE_TAG" \
  "org.opencontainers.image.licenses=BUSL-1.1" \
  "org.opencontainers.image.title=TeleCrypt Controlplane" \
  "org.opencontainers.image.description=TeleCrypt Registration, Janitor, and Plan services" \
  "org.opencontainers.image.vendor=TeleCrypt.io" \
  "io.telecrypt.config-contract=1" \
  "org.telecrypt.controlplane.release=$RELEASE_TAG" \
  "org.telecrypt.tier-controller.release=$RELEASE_TAG"; do
  label_name="${label_expectation%%=*}"
  expected_value="${label_expectation#*=}"
  actual_value="$(capture_value image inspect --format "{{index .Config.Labels \"$label_name\"}}" "$IMAGE_REF")"
  [[ "$actual_value" == "$expected_value" ]] || {
    echo "image label $label_name=$actual_value does not match $expected_value" >&2
    exit 1
  }
done

[[ "$(capture_value image inspect --format '{{.Config.User}}' "$IMAGE_REF")" == "991:991" ]] || {
  echo "image user is not 991:991" >&2
  exit 1
}
[[ "$(capture_value image inspect --format '{{json .Config.Entrypoint}}' "$IMAGE_REF")" == "null" ]] || {
  echo "image Entrypoint must be unset" >&2
  exit 1
}
[[ "$(capture_value image inspect --format '{{json .Config.Cmd}}' "$IMAGE_REF")" == '["/registration"]' ]] || {
  echo "image default command must be [\"/registration\"]" >&2
  exit 1
}
