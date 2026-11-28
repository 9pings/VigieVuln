# How the code is organised

`vigievuln.js` at the repository root is the executable. It routes each command to one of
the entry points below, and runs the project scan (`scan <path>`) itself.

## Where it starts: the files at the root of `lib/`

| File | What starts there |
|---|---|
| `cli-command-routing.js` | maps the command line (`scan`, `system`, `cache`, `account`…) to an entry point |
| `cli-image.js` | `system scan`: images, archives, root filesystems, inventories, SBOMs |
| `cli-collect.js` | `system collect`: inventory of a live system or a root filesystem |
| `cli-project-commands.js` | account and hosted-project commands |
| `cli-setup.js` | `setup`: interactive configuration |
| `cli-watch.js` | `watch`: rescan on change |
| `cli-groups.js` | option groups and report formats (`-r html,json…`) |
| `options-env.js` | how an option is resolved: command line, environment, configuration file |
| `config.js` | the user configuration file (`~/.vigie-vuln/config.json`) |
| `source-input.js` | the scanned source: a directory or an archive |
| `ui.js` | terminal output: banner, sections, colours |

Nothing else lives at the root of `lib/`. A new module goes in the folder of its theme.

## Folders

| Folder | Content |
|---|---|
| `providers/` | One folder per data source. `providers/index.js` is the single entry point for every network lookup (cache, proxy or direct request). `providers/<name>/index.js` describes the source's requests; the other files of the folder are everything specific to that source: parsing, enrichment, matching rules. |
| `codecs/` | One codec per ecosystem (Maven, Gradle, npm, Yarn, PyPI, Composer, Go, NuGet, Ruby, binaries): manifests, lockfiles, registry metadata, version ordering. `codecs/maven/` holds the POM model, reactor, BOMs and transitive resolution. |
| `inventory/` | The dependency model shared by every codec (`dep-record.js`), descriptors, package URLs, private and unmanaged components, directory walking. |
| `advisories/` | The advisory store and the matching of native CVE records against packages. |
| `findings/` | What happens to a match once found: merging sources, severity, priority, enrichment, evidence, attribution, suppression, CI gate, differential audit. |
| `scan/` | Facts about a run: coverage, reliability and the publication policy, diagnostics, source health, provenance. |
| `reports/` | HTML and Word report, JSON, CycloneDX, SARIF, CSAF and Excel exports, charts, localisation. |
| `cache/` | SQLite cache, cache archives for air-gapped use, the proxy cache, the pull-through resource cache (`cache/resource/`). |
| `images/` | Image references in source trees, registry client, local Docker engine, extraction roots. |
| `artifacts/` | Acquisition and assessment of system targets: layers, disks, installed applications, binaries, SBOM input. |
| `system-inventory/` | Installed packages of a system and their assessment against distribution advisories. |
| `applications/` | CMS and framework instances: inventory, layout, exports; `applications/plugins/` has one plugin per application type. |
| `maintenance/` | End of life, obsolete and outdated components, commercial support. |
| `certs/` | Certificates and keys found in a tree. |
| `service/` | Client of the hosted account and project service. |

## Rules

- Code specific to one data source goes in `providers/<name>/`, next to that source's
  request descriptor. A folder that serves several sources stays generic.
- Code specific to one ecosystem goes in `codecs/<ecosystem>/`.
- The server repository loads some of these modules by path (`vigievuln/lib/<name>`). The
  `exports` map of `package.json` keeps the paths it knows working when a file moves. After
  moving or removing a module, run `node scripts/check-server-modules.js ../server`.
