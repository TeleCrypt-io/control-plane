#!/usr/bin/env bash

capture_active_pid=""
capture_active_output=""
capture_active_stderr=""
capture_active_replay_output=true

capture_command_signal() {
  local signal_name="$1" status=143 kill_status wait_status replay_status=0 failure_status=0
  case "$signal_name" in
    HUP) status=129 ;;
    INT) status=130 ;;
    TERM) status=143 ;;
    *) status=143 ;;
  esac
  set +e
  if [[ -n "$capture_active_pid" ]]; then
    kill -0 "$capture_active_pid"
    kill_status=$?
    if [[ "$kill_status" -eq 0 ]]; then
      kill -TERM "$capture_active_pid"
      kill_status=$?
      if [[ "$kill_status" -ne 0 ]]; then
        printf 'captured command child termination failed during %s (status %s)\n' "$signal_name" "$kill_status" >&2
        failure_status=1
      fi
    elif [[ "$kill_status" -ne 1 ]]; then
      printf 'captured command child liveness check failed during %s (status %s)\n' "$signal_name" "$kill_status" >&2
      failure_status=1
    fi
    wait "$capture_active_pid"
    wait_status=$?
    capture_active_pid=""
    if [[ "$wait_status" -ne 0 && "$wait_status" -ne 143 ]]; then
      printf 'captured command child wait failed during %s (status %s)\n' "$signal_name" "$wait_status" >&2
      failure_status=1
    fi
    if [[ "$wait_status" -eq 0 ]]; then
      printf 'captured command child exited successfully while handling %s\n' "$signal_name" >&2
    fi
  fi
  if [[ -n "$capture_active_output" && "$capture_active_replay_output" == true ]] && ! cat -- "$capture_active_output" >&2; then
    replay_status=1
  fi
  if [[ -n "$capture_active_stderr" ]] && ! cat -- "$capture_active_stderr" >&2; then
    replay_status=1
  fi
  if (( replay_status != 0 )); then
    printf 'captured command diagnostics could not be replayed after %s\n' "$signal_name" >&2
    failure_status=1
  fi
  if (( failure_status != 0 )); then status=1; fi
  exit "$status"
}

capture_command() {
  local replay_output=true
  if [[ "${1:-}" == --binary-output ]]; then
    replay_output=false
    shift
  fi
  local output="$1" timeout_seconds="$2" stderr_file="${1}.stderr" status replay_status=0
  shift 2
  [[ "$timeout_seconds" =~ ^[0-9]+$ && "$timeout_seconds" -gt 0 ]] || return 2
  local previous_hup previous_int previous_term
  previous_hup="$(trap -p HUP || true)"
  previous_int="$(trap -p INT || true)"
  previous_term="$(trap -p TERM || true)"
  capture_active_output="$output"
  capture_active_stderr="$stderr_file"
  capture_active_replay_output="$replay_output"
  trap 'capture_command_signal HUP' HUP
  trap 'capture_command_signal INT' INT
  trap 'capture_command_signal TERM' TERM
  set +e
  timeout --signal=TERM --kill-after=5s "${timeout_seconds}s" "$@" >"$output" 2>"$stderr_file" &
  capture_active_pid="$!"
  wait "$capture_active_pid"
  status="$?"
  set -e
  capture_active_pid=""
  capture_active_output=""
  capture_active_stderr=""
  capture_active_replay_output=true
  if [[ -n "$previous_hup" ]]; then eval "$previous_hup"; else trap - HUP; fi
  if [[ -n "$previous_int" ]]; then eval "$previous_int"; else trap - INT; fi
  if [[ -n "$previous_term" ]]; then eval "$previous_term"; else trap - TERM; fi
  if (( status != 0 )); then
    if [[ "$replay_output" == true ]] && ! cat -- "$output" >&2; then
      replay_status=1
    fi
    if ! cat -- "$stderr_file" >&2; then
      replay_status=1
    fi
    if (( replay_status != 0 )); then
      printf 'captured command diagnostics could not be replayed (command status %s)\n' "$status" >&2
    fi
    return "$status"
  fi
  if ! cat -- "$stderr_file" >&2; then
    printf 'captured command stderr could not be emitted\n' >&2
    return 1
  fi
  return 0
}

replay_capture() {
  local output="$1" stderr_file="${2:-${1}.stderr}" status=0
  if ! cat -- "$output" >&2; then status=1; fi
  if ! cat -- "$stderr_file" >&2; then status=1; fi
  return "$status"
}

capture_jq() {
  local output="$1" status
  shift
  if jq -e "$@" "$output" >/dev/null; then
    return 0
  else
    status="$?"
  fi
  replay_capture "$output" ||
    printf 'captured response diagnostics could not be replayed\n' >&2
  return "$status"
}

capture_extract() {
  local variable="$1" output="$2" value status
  shift 2
  if value="$(jq -er "$@" "$output")"; then
    printf -v "$variable" '%s' "$value"
    return 0
  else
    status="$?"
  fi
  replay_capture "$output" ||
    printf 'captured response diagnostics could not be replayed\n' >&2
  return "$status"
}

ghcr_version_records() {
  local page_json="$1" release_tag="$2" build_digest="$3"
  jq -e '
    type == "array" and length <= 100 and
    all(.[];
      type == "object" and
      (.id | type == "number" and . > 0 and . == floor) and
      (.name | type == "string" and test("^sha256:[0-9a-f]{64}$")) and
      (.metadata | type == "object" and .package_type == "container") and
      (.metadata.container | type == "object") and
      (.metadata.container.tags | type == "array" and
        all(.[]; type == "string" and test("^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$")) and
        (length == (unique | length)))
    )' "$page_json" >/dev/null || return 1
  jq -r --arg tag "$release_tag" --arg digest "$build_digest" '
    .[] |
    [
      (.id | tostring),
      .name,
      ([.metadata.container.tags[] | select(. == $tag)] | length | tostring),
      (if .name == $digest then "1" else "0" end)
    ] | @tsv
  ' "$page_json"
}
