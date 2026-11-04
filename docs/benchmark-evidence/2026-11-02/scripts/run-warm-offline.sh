#!/bin/sh
set -u
for spec in nodegoat:npm prometheus:go poetry:pypi mastodon:ruby phpmyadmin:composer; do
 name=${spec%:*}; eco=${spec#*:}
 if [ "$name" = poetry ]; then exclude="--exclude-path=tests/**"; else exclude=''; fi
 node /app/vigievuln.js scan "/projects/$name" --advisory-query-ttl 0 --offline --retries 0 --ecosystem "$eco" --app-plugins none --no-gcve --no-nvd --no-epss --no-kev --no-certfr --no-euvd --no-eol --no-retire --no-packagist-audit --no-all-libs --no-binaries --no-jars --no-certs $exclude --report-json "/out/$name-vv-warm-offline.json" --report-output "/out/$name-warm-offline-report" > "/out/$name-vv-warm-offline.log" 2>&1
 code=$?; printf '%s scan_exit=%s\n' "$name" "$code"
 if [ "$code" -ne 0 ]; then tail -n 15 "/out/$name-vv-warm-offline.log"; exit "$code"; fi
done
