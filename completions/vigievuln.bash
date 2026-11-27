#!/usr/bin/env bash
# Bash completion for vigievuln (VigieVuln — autonomous dependency auditor)
# Source this file or copy it to /etc/bash_completion.d/vigievuln
_fad_check_complete() {
	local cur prev opts
	COMPREPLY=()
	cur="${COMP_WORDS[COMP_CWORD]}"
	prev="${COMP_WORDS[COMP_CWORD-1]}"
	opts="--vigievuln-proxy --proxy-cache --proxy-cache-token --target --exclude --verbose --force-update --no-report --no-transitive --no-all-libs --no-osv --no-nvd --no-epss --no-kev --licenses --no-retire --retire-refresh --report-output --report-html --report-doc --report-xlsx --report-sbom --report-csaf --report-json --report-sarif --fail-on --fail-on-new --baseline --no-checksums --ignore --vex --ignore-test --cve-refresh --cve-offline --snyk --transitive-depth --offline --ecosystem --no-maven --no-npm --no-yarn --no-nuget --no-composer --no-pypi --no-go --no-ruby --no-jars --no-binaries --no-certs --cert-expiry-days --retries --no-nvd-mirror --eol-support --no-eol --no-js --set-nvd-key --show-config --completion --help --version --disable --activate --report --help-all -t -e -h -v -d -a -r -o"
	if [[ "$COMP_CWORD" -eq 1 ]]; then
		COMPREPLY=( $(compgen -W "scan system watch login logout whoami setup config cache" -- "$cur") )
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
			COMPREPLY=( $(compgen -W "auto all maven npm yarn nuget composer pypi" -- "$cur") )
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
