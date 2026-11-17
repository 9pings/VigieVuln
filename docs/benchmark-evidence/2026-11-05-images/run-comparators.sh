#!/usr/bin/env bash
# Run only after preparing the recorded OCI layouts and frozen comparator DBs.
set -euo pipefail
benchmark_root=${BENCHMARK_ROOT:-/tmp/vv-image-benchmark-20261105}
scanner_bin=${SCANNER_BIN:-/tmp/vigie-scanner-benchmark-20261102/bin}
export GRYPE_DB_CACHE_DIR="$benchmark_root/grype-cache"
export GRYPE_DB_AUTO_UPDATE=false
export GRYPE_CHECK_FOR_APP_UPDATE=false
for image in traefik nginx; do
  input="$benchmark_root/$image/oci"
  case "$image" in
    traefik) digest=903f89ddacc3059657565d3e5b3b8e8dcba4cc3b8af08183dad6fdc415459111 ;;
    nginx) digest=2e26275ed7a47e8e93f264d39a09ca4bc3f4058c904c75087e237f4ea883f2a1 ;;
  esac
  printf '%s  %s\n' "$digest" "$input/blobs/sha256/$digest" | sha256sum --check --status
  node -e 'const x=require(process.argv[1]); if(x.manifests.length!==1 || x.manifests[0].digest!=="sha256:"+process.argv[2]) process.exit(1)' "$input/index.json" "$digest"
  "$scanner_bin/trivy" image --cache-dir "$benchmark_root/trivy-cache" --skip-db-update --skip-java-db-update --offline-scan --scanners vuln --list-all-pkgs --format json --output "$benchmark_root/$image/trivy.json" --input "$input" > "$benchmark_root/$image/trivy.log" 2>&1
  "$scanner_bin/grype" "oci-dir:$input" --scope squashed --output json --file "$benchmark_root/$image/grype.json" > "$benchmark_root/$image/grype.log" 2>&1
  "$scanner_bin/grype" "oci-dir:$input" --scope squashed --output cyclonedx-json --file "$benchmark_root/$image/grype.cdx.json" > "$benchmark_root/$image/grype-cdx.log" 2>&1
done
