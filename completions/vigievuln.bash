#!/usr/bin/env bash
# Bash completion for vigievuln (VigieVuln — autonomous dependency auditor)
# Source this file or copy it to /etc/bash_completion.d/vigievuln
_fad_check_complete() {
	local cur prev opts
	COMPREPLY=()
	cur="${COMP_WORDS[COMP_CWORD]}"
	prev="${COMP_WORDS[COMP_CWORD-1]}"
	opts="--activate --add-repo --advisory-config --advisory-query-ttl --allow-insecure-http --app-plugins --auth --baseline --cache-dir --cert-expiry-days --completion --config --cve-offline --cve-refresh --definitions --disable --distribution --docker --docker-socket --drupal-advisories --drupal-advisories-live --ecosystem --enrich --eol-support --exclude --exclude-path --expected-digest --export --export-anonymized --export-cache --export-inventory --fail-on --fail-on-incomplete --fail-on-new --force --force-update --gcve-offline --help --help-all --id --ignore --ignore-test --image --image-platform --image-retire --images --import-advisories --import-anonymized --import-cache --include-config --insecure --inventory --lang --licenses --limits --list-app-plugins --list-repos --max-advisory-age --name --no-all-libs --no-binaries --no-certfr --no-certs --no-checksums --no-composer --no-default-excludes --no-distro-advisories --no-eol --no-eol-support --no-epss --no-euvd --no-gcve --no-go --no-gradle --no-image-retire --no-images --no-jars --no-js --no-kev --no-maven --no-npm --no-nuget --no-nvd --no-nvd-mirror --no-osv --no-osv-db --no-packagist-audit --no-ruby-advisories --no-publisher-advisories --no-pypi --no-report --no-retire --no-reuse-stable-advisories --no-ruby --no-transitive --no-vendored-js-inventory --no-yarn --nvd-cpe-match --offline --osv-db --osv-db-refresh --output --platform --prefer-sbom --prepare-cache --prepare-offline --prepare-project --prestashop-advisories --prestashop-advisories-live --private-component --projects --proxy --proxy-cache --proxy-cache-token --proxy-rate-limit-wait-ms --public-component --registry --registry-auth --remove-repo --replace --repo --report --report-csaf --report-doc --report-html --report-json --report-output --report-sarif --report-sbom --report-xlsx --reports --retire-refresh --retries --reuse-stable-advisories --sbom --scan-context --set-nvd-key --set-proxy-cache --set-proxy-cache-token --show-config --snapshot-complete --snyk --source-profile --spip-advisories --spip-advisories-live --src --stable-advisory-age-days --sync-advisories --target --token --transitive-depth --typo3-advisories --typo3-advisories-live --typosquat --unset-proxy-cache --unset-proxy-cache-token --verbose --version --vex --vigievuln-proxy --wordfence-api-key --wordfence-feed --wordfence-feed-url --wordfence-live --wp-checksums --wp-checksums-live --wp-checksums-locale"
	if [[ "$COMP_CWORD" -eq 1 ]]; then
		COMPREPLY=( $(compgen -W "scan system watch login logout whoami setup config cache diff serve-cache" -- "$cur") )
		return 0
	fi
	if [[ "${COMP_WORDS[1]}" == system && "$COMP_CWORD" -eq 2 ]]; then
		COMPREPLY=( $(compgen -W "collect scan" -- "$cur") )
		return 0
	fi
	case "$prev" in
		scan|collect)
			COMPREPLY=( $(compgen -f -- "$cur") )
			return 0 ;;
		--target|-t|--report-output|-o)
			COMPREPLY=( $(compgen -d -- "$cur") )
			return 0 ;;
		--vigievuln-proxy)
			COMPREPLY=( $(compgen -W "fr com" -- "$cur") )
			return 0 ;;
		--ecosystem)
			COMPREPLY=( $(compgen -W "auto all maven gradle npm yarn nuget composer pypi go ruby binary" -- "$cur") )
			return 0 ;;
		--completion)
			COMPREPLY=( $(compgen -W "bash zsh" -- "$cur") )
			return 0 ;;
	esac
	if [[ "$cur" == -* ]]; then
		COMPREPLY=( $(compgen -W "$opts" -- "$cur") )
		return 0
	fi
}
complete -F _fad_check_complete vigievuln fad-checker fad
