#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
: "${TEST_DATABASE_URL:?Set TEST_DATABASE_URL to a disposable PostgreSQL 17 test database}"
export GO_VERSION=1.26.4 PYTHON_VERSION=3.12.14 SYNAPSE_VERSION=1.159.0 SYNAPSE_IMAGE=ghcr.io/element-hq/synapse:v1.159.0
workspace="$PWD"
work_dir="$(mktemp -d)"
trap 'rm -rf -- "$work_dir"' EXIT

# Use the same toolchain as the release image.
[[ "$(go env GOVERSION)" == "go$GO_VERSION" ]]
[[ "$(python3 -c 'import platform; print(platform.python_version())')" == "$PYTHON_VERSION" ]]
# Replace generated build output from a previous local check.
rm -rf -- dist/tier-controller

# Test Go services
go test ./...

# Vet Go services
go vet ./...

# Build and test tier-controller wheel
set -euo pipefail
test_wheelhouse=$work_dir/wheelhouse
rm -rf -- "$test_wheelhouse"
mkdir -p "$test_wheelhouse"
python3 -m pip download --disable-pip-version-check --only-binary=:all: --no-deps --require-hashes \
  --dest "$test_wheelhouse" -r synapse-policy/requirements-test.txt
python3 -m venv "$work_dir/venv"
python_bin=$work_dir/venv/bin/python
"$python_bin" -m pip install --disable-pip-version-check --no-index \
  --find-links="$test_wheelhouse" --require-hashes -r synapse-policy/requirements-test.txt
"$python_bin" -c 'import setuptools; assert setuptools.__version__ == "84.0.0"'
"$python_bin" -m build --no-isolation --wheel --outdir dist/tier-controller .
timeout --signal=TERM --kill-after=5s 120s docker pull "$SYNAPSE_IMAGE"
timeout --signal=TERM --kill-after=5s 120s docker run --rm -i --user 0:0 \
  --env PIP_ROOT_USER_ACTION=ignore \
  --mount "type=bind,src=$workspace/dist/tier-controller,dst=/wheel,readonly" \
  --mount "type=bind,src=$workspace/synapse-policy/test_tier_controller.py,dst=/work/test_tier_controller.py,readonly" \
  --entrypoint python "$SYNAPSE_IMAGE" - <<'PY'
import pathlib, site, subprocess, sys
wheel = next(pathlib.Path('/wheel').glob('*.whl'))
subprocess.run([sys.executable, '-m', 'pip', 'install', '--no-index', '--no-deps', '--target', site.getsitepackages()[0], str(wheel)], check=True)
subprocess.run([sys.executable, '/work/test_tier_controller.py'], check=True)
PY


# Check tested wheel
set -euo pipefail
shopt -s nullglob
wheels=(dist/tier-controller/*.whl)
[[ "${#wheels[@]}" -eq 1 ]]
wheel="${wheels[0]##*/}"
(cd dist/tier-controller && sha256sum "$wheel" >"$wheel.sha256" && sha256sum --strict --check "$wheel.sha256")
files=(dist/tier-controller/*)
[[ "${#files[@]}" -eq 2 ]]
[[ "$(wc -c <"${wheels[0]}")" -le 67108864 ]]

