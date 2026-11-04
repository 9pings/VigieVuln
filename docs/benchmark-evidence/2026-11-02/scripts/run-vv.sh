#!/bin/sh
set -u
for spec in nodegoat:npm prometheus:go poetry:pypi mastodon:ruby phpmyadmin:composer; do
  name=${spec%:*}
  eco=${spec#*:}
  node /app/vigievuln.js scan "/projects/$name" --offline --ecosystem "$eco" --app-plugins none --no-gcve --no-nvd --no-epss --no-kev --no-certfr --no-euvd --no-eol --no-retire --no-packagist-audit --no-all-libs --no-binaries --no-jars --no-certs --report-json "/out/$name-vv.json" --report-output "/out/$name-report" > "/out/$name-vv.log" 2>&1
  code=$?
  printf '%s scan_exit=%s\n' "$name" "$code"
  if [ "$code" -ne 0 ]; then tail -n 15 "/out/$name-vv.log"; exit "$code"; fi
done
