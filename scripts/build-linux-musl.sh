#!/bin/sh
# Build and exercise the release archive before making it available in dist/.
set -eu
cd "$(dirname "$0")/.."
version=$(node -p 'require("./package.json").version')
alpine='alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc'
destination=$(realpath -m "${1:-dist}")
mkdir -p "$destination"
stage=$(mktemp -d "$destination/.linux-x64-musl.XXXXXXXX")
trap 'rm -r -- "$stage"' EXIT
archive="vigievuln-linux-x64-musl-v${version}.tar.gz"

bun build vigievuln.js --compile --target=bun-linux-x64-musl --outfile="$stage/vigievuln"
# Bun's musl executable dynamically links libstdc++, which also uses libgcc.
# Resolve both beside the executable even on a stock Alpine installation.
docker run --rm --platform linux/amd64 -v "$stage/vigievuln:/input:ro" -v "$PWD/node_modules/7z-wasm:/wasm:ro" -v "$PWD/licenses/7z-wasm:/notices:ro" -v "$PWD/node_modules/@renovatebot/pep440:/pep:ro" "$alpine" sh -ec '
  apk add --no-cache libstdc++ patchelf >&2
  mkdir -p /bundle/lib /bundle/licenses
  cd /bundle
  mkdir licenses/7z-wasm licenses/pep440
  cp /pep/LICENSE* licenses/pep440/
  cp /wasm/License.txt /wasm/unRarLicense.txt /notices/LGPL-2.1.txt licenses/7z-wasm/
  cp /input vigievuln
  cp -L /usr/lib/libstdc++.so.6 /usr/lib/libgcc_s.so.1 lib/
  patchelf --set-rpath '\''$ORIGIN/lib'\'' vigievuln
  base=https://raw.githubusercontent.com/gcc-mirror/gcc/releases/gcc-13.2.0
  wget -qO licenses/COPYING3 "$base/COPYING3"
  wget -qO licenses/COPYING.RUNTIME "$base/COPYING.RUNTIME"
  echo "8ceb4b9ee5adedde47b31e975c1d90c73ad27b6b165a1dcd80c7c545eb65b903  licenses/COPYING3" | sha256sum -c - >&2
  echo "9d6b43ce4d8de0c878bf16b54d8e7a10d9bd42b75178153e3af6a815bdc90f74  licenses/COPYING.RUNTIME" | sha256sum -c - >&2
  apk info -v -e libstdc++ libgcc > licenses/alpine-packages.txt
  test "$(./vigievuln --version)" = "$1"
  touch -t 197001010000.00 vigievuln lib/* licenses/*
  tar -czf - vigievuln lib/libstdc++.so.6 lib/libgcc_s.so.1 licenses/COPYING3 licenses/COPYING.RUNTIME licenses/alpine-packages.txt licenses/7z-wasm licenses/pep440
' sh "$version" > "$stage/$archive"

mkdir "$stage/bundle" "$stage/output"
tar -xzf "$stage/$archive" -C "$stage/bundle"
docker run --rm --platform linux/amd64 --pull never --network none --read-only \
  --user "$(id -u):$(id -g)" -e HOME=/nonexistent \
  -v "$stage/bundle:/opt/vigie:ro" -v "$PWD/test/fixtures/polyglot:/srv/demo:ro" \
  -v "$stage/output:/output" "$alpine" sh -ec '
    if command -v node || command -v bun; then exit 1; fi
    test ! -e /usr/lib/libstdc++.so.6
    exec /opt/vigie/vigievuln system collect / --output /output/inventory.json
  '
node - "$stage/output/inventory.json" <<'JS'
const assert = require('node:assert/strict');
const {readSnapshot} = require('./lib/artifacts/scan');
const [host] = readSnapshot(process.argv[2]);
assert.equal(host.distribution.id, 'alpine');
assert.match(host.distribution.versionId, /^3\.20(?:\.|$)/);
assert.ok(host.packages.some(pkg => pkg.manager === 'apk' && pkg.name === 'busybox'));
for (const [name, version, file] of [
  ['lodash', '4.17.21', 'js/package-lock.json'],
  ['guzzle', '7.4.5', 'php/composer.lock'],
]) {
  assert.ok(host.deps.some(dep => dep.provenance === 'lockfile' && dep.name === name &&
    dep.version === version && dep.artifactPath === 'srv/demo/' + file), file);
}
console.log('Validated Alpine ' + host.distribution.versionId + ', APK inventory and PHP/JS lockfiles.');
JS
mv "$stage/$archive" "$destination/$archive"
sha256sum "$destination/$archive"
