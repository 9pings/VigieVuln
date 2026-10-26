# Scanner benchmark: full capability, and with no network

Five scanners on one public project, measured two ways. Everything here is reproducible — the
target is pinned to a commit, the commands are below, and every number can be recomputed from
the tools' own JSON output. Run it and tell me if it doesn't hold.

Spoiler for the impatient, so nothing here reads as a sales pitch: **at full capability no tool
finds everything** — vigievuln leads at 87% of the union, and 118 pairs were reported by Snyk
and not by it. Those 118 were published here as a recall gap; they are not one. Every pair has
since been adjudicated against the public record and **none is a recall bug** —
[the measurement](#what-vigievuln-misses-and-why). Its differentiator remains the second table:
what survives when the network is gone.

> **Re-measured — 2026-10-02, after the Maven mediation fixes** (dependencyManagement-only
> pins no longer scanned, `<exclusions>` and managed scopes applied, import-BOM versions pinning
> transitives — see CHANGELOG). Same pinned commit, same unit. OSV-Scanner online now reports
> **705** pairs (its database grew since the table below): fad recovers **705/705 online and
> 705/705 under `unshare -rn --offline`**, before and after the fixes. The fixes remove **71**
> fad pairs and add none; **none of the 71 is reported by OSV-Scanner**, and each was checked
> against `mvn dependency:tree` on the declaring modules: `jackson-databind`/`jackson-core`
> **2.4.3** (55 pairs — no module resolves 2.4.3), `io.netty:netty:3.10.6.Final` (13 — excluded
> from zookeeper), `grpc-netty-shaded:1.22.1` (managed only; its declaration is commented out),
> `commons-httpclient:3.0.1` and `junit:4.11` (on no classpath of the modules they were filed
> under). fad goes from 883 to 812 pairs: those 71 were false positives.
>
> **Second pass, same day — Maven resolved module by module** (`lib/maven-reactor.js`, plus
> Maven's own version ordering and deterministic nearest-wins). OSV-Scanner recall stays
> **705/705 online and air-gapped**. fad goes from 812 to **834** pairs: **−9** that were false
> positives — `jetty-server`/`jetty-http` `9.4.11.v20180605` for CVE-2017-7656/7657/7658 and
> CVE-2018-12536, all fixed IN 9.4.11 (the old ordering ranked `.v20180605` below 9.4.11), and a
> CVE filed on the `spring-framework-bom` POM — and **+31** real ones the global pass masked:
> netty **4.1.35.Final** (`netty-codec`/`-handler`/`-codec-http`/`-common`) in dubbo-rpc-grpc,
> `netty-all` **4.1.25.Final** in dubbo-rpc-rest, `jetty-util` 9.4.11.v20180605 — every one of
> them present at that version and scope in `mvn dependency:tree` of the module it is filed
> under. Air-gapped wall clock, warm cache: about 1 s.

## Two different questions

A scanner comparison usually conflates two things. This one separates them, because the
answers are not the same.

1. **At full capability, what does each tool find?** Every scanner online, in its best
   configuration, with a populated `~/.m2`. This is the fair product comparison.
2. **With no network, what survives?** The narrower question vigievuln is built around.

Target for both: **Apache Dubbo 2.7.8**, a 105-module Maven reactor
(`0be2a1bbbf9168490acecaf1eed1bd16cb8db402`).

Unit: distinct `(coordinate@version | vulnerability)` pairs, Maven only, GHSA and `SNYK-*` ids
mapped to their CVE alias so every tool sits on one identifier space. Dubbo's **own**
`org.apache.dubbo` artifacts are excluded on every side: OSV-Scanner filters reactor modules as
"local/unscannable", so counting them would flatter whoever does scan them.

## 1. Full capability

Union of everything any tool found: **908** pairs.

| Scanner, best configuration | Found | Unique to it | % of union | Not reported¹ |
| --- | --- | --- | --- | --- |
| **vigievuln 2.4.6** | **790** | 125 | **87.0%** | 118 → **0 real**¹ |
| OSV-Scanner 2.4.0 (online) | 657 | 0 | 72.4% | 251 |
| Snyk 1.1302.1 (`--all-projects`, mvn build) | 603 | **117** | 66.4% | 305 |
| Trivy 0.72.0 (populated `~/.m2`) | 546 | 0 | 60.1% | 362 |
| Grype 0.116.0 + Syft 1.49.0 | 45 | 0 | 5.0% | 863 |

¹ **"Not reported" is union arithmetic, not a verified recall gap.** It counts pairs some other
tool produced and this one did not — which is only a miss if the public record actually binds that
vulnerability to that coordinate and version. For vigievuln that was checked, pair by pair:
**0 of them are recall bugs**, and two thirds are Snyk contradicting the public record
([detail](#what-vigievuln-misses-and-why)). The other rows have *not* been adjudicated, so read
their column the same way — as "did not report", not "missed".

Read the other rows fairly too: Trivy and Grype are **container and SBOM scanners**; a raw Maven
source checkout is not the job they are built for.

Snyk and Trivy at full capability both depend
on a real Maven build having happened — Snyk invokes `mvn`, and Trivy needs either network access
or a `~/.m2` that a previous build populated. vigievuln and OSV-Scanner read the tree without
building. That is a different starting assumption, not a better one, and it is the reason the
second table exists.

Two measured details worth stating rather than assuming. **Trivy's result is identical online and
with a fully populated `~/.m2`** (559 raw pairs either way) — the local repository fully
substitutes for the network. **Grype+Syft does not move at all**: 58 raw pairs with defaults, 58
with `java.use-network=true` and `java.resolve-transitive-dependencies=true`, because that option
is scoped to archives, not to `pom.xml` source scanning.

## 2. No network at all

Same tree, every scanner under `unshare -rn`, in a namespace with **no network interface** —
not merely an offline flag. Reference: OSV-Scanner's own **online** output, 657 pairs.

| Scanner, no network | Recovers | Wall clock |
| --- | --- | --- |
| **vigievuln 2.4.6** `--offline` | **657 (100%)** | 4.5 s |
| Grype + Syft (defaults) | 45 (6.8%) | 32 s |
| Trivy `--offline-scan`, cold `~/.m2` | 40 (6.1%) | 1.0 s |
| OSV-Scanner `--offline` | 37 (5.6%) | 0.8 s |

100% here means "recovers everything OSV-Scanner finds **with** network access", not "finds
everything that exists" — table 1 is the honest answer to that, and there fad sits at 87%.
OSV-Scanner returns the identical 37 with and without the namespace: it behaves exactly as
documented, it is not failing.

The mechanism is in OSV-Scanner's own documentation:

> "OSV-Scanner supports transitive dependency scanning for Maven pom.xml. This feature is enabled
> by default when scanning, but it can be disabled using the `--no-resolve` flag. **It is also
> disabled in the offline mode.**"
> — [supported languages and lockfiles](https://google.github.io/osv-scanner/supported-languages-and-lockfiles/)

Online, OSV-Scanner finds 92 vulnerable Maven packages on this project. Offline it finds 3. The
missing 89 are transitive.

Note the asymmetry between the two Trivy rows: 40 pairs on a cold `~/.m2`, 546 once a build has
populated it. Trivy's dependency is on *a resolved local repository*, which the network or a
prior build can supply. fad's cache is coordinate-keyed and travels
(`--export-cache` / `--import-cache`), which is what makes the air-gapped workflow work.

## Per-ecosystem results

Maven is where vigievuln's design pays off, so it gets its own deep dive above. But it
claims ten ecosystems, and "we benchmarked one of them" is not an answer. Here are the others,
same method: OSV-Scanner and vigievuln on the same public project, findings normalised to
`(package@version | CVE)` with GHSA/PYSEC ids mapped to their CVE alias.

**Expect parity, and that is the point.** For npm, PyPI, Go, RubyGems and Composer the
transitive graph is *in the lockfile*. Every tool reads the same file, so no scanner has a
structural advantage and none should. Maven is the exception because its graph is not in the
tree at all — it has to be resolved from the registry, which is why an offline gap exists there
and nowhere else.

### Targets

| Ecosystem | Project | Pinned at | Manifest read |
| --- | --- | --- | --- |
| Maven | [apache/dubbo](https://github.com/apache/dubbo) 2.7.8 | `0be2a1bb` | 105 × `pom.xml` |
| npm | [OWASP/NodeGoat](https://github.com/OWASP/NodeGoat) | `c5cb68a` | `package-lock.json`, 1 927 entries |
| Go | [prometheus/prometheus](https://github.com/prometheus/prometheus) v2.30.0 | `37468d8` | `go.mod` (go 1.14, 97 requires) + `go.sum` (578 modules) |
| PyPI | [python-poetry/poetry](https://github.com/python-poetry/poetry) 1.1.15 | `46bf7fd` | `poetry.lock`, 91 packages |
| RubyGems | [mastodon/mastodon](https://github.com/mastodon/mastodon) v3.5.3 | `fbcbf78` | `Gemfile.lock`, 426 specs |
| Composer | [phpmyadmin/phpmyadmin](https://github.com/phpmyadmin/phpmyadmin) 5.1.1 | `ed65cd2` | `composer.lock`, 224 entries |

Real projects pinned to a released tag, not synthetic fixtures — old enough to carry genuine
vulnerabilities, and reproducible by anyone.

### Results

| Ecosystem | OSV-Scanner | vigievuln | Both | fad only | OSV only |
| --- | --- | --- | --- | --- | --- |
| Maven | 657 | **790** | 657 | 133 | 0 |
| npm | 274 | 274 | **274** | 0 | 0 |
| RubyGems | 150 | 150 | **150** | 0 | 0 |
| Composer¹ | 34 | 34 | **34** | 0 | 0 |
| Go | 113 | 110 | 110 | 0 | 3 |
| PyPI | 83 | 79 | 79 | 0 | 4 |

**npm, RubyGems and Composer: identical sets, not merely equal counts.** Zero difference in
either direction. That is the expected and correct result when both tools read the same
lockfile, and it is worth publishing precisely because it is unremarkable.

¹ **Composer needed `--no-ignore`.** phpMyAdmin's `.gitignore` lists `composer.lock` on line 57
even though the file is committed, and OSV-Scanner honours `.gitignore` by default, so its
recursive scan skipped the lockfile entirely and reported 0 Packagist findings. Pointed straight
at the file it finds the same 34. Not a bug on either side, a policy difference: fad scans what
is **on disk**, which for an audit is the right answer — a gitignored-but-present lockfile still
describes what will be installed.

**Go — 3 pairs, version selection.** `golang.org/x/sys` at a pseudo-version and
`gopkg.in/yaml.v2@2.2.4`: OSV reads the version from `go.mod`, fad takes the highest version
carrying a zip hash in `go.sum`. 

**PyPI — 4 pairs, and fad is arguably right.** All four are `setuptools@9.1.0`, which
OSV-Scanner picked up from `tests/utils/fixtures/setups/ansible/requirements.txt` — a **test
fixture inside poetry's own test suite**, not a dependency of the project. fad reads
`poetry.lock`, which is authoritative, and ignores stray requirements files when a lockfile
exists.

### What parity does not measure

Equal CVE counts do not make two tools equivalent. On these same projects fad additionally
reported, and OSV-Scanner does not attempt: **1 120 outdated** dependencies and 58 deprecated on
mastodon, **618 outdated** and 2 EOL frameworks on phpMyAdmin, 65 outdated on poetry. Whether
that is signal or noise is the auditor's call — the point is that it is a different question,
not a better score on the same one.

### The air-gapped descriptor, outside Maven

The offline *recall* gap is Maven-only, but the anonymized-descriptor workflow is not — and it
matters more outside Maven, because a `package-lock.json` names internal packages and carries
private registry URLs. Measured on the npm target, same project both sides:

| | fad `--export-anonymized` | Syft SBOM |
| --- | --- | --- |
| Entries | 804 deps | 419 components |
| File paths | **absent** | present (`syft:location`) |
| Registry URLs | **absent** | present |
| Integrity hashes | **absent** | present |

The descriptor carries `ecosystem, ecosystemType, namespace, name, version, versions, scope,
isDev` and nothing else. An SBOM is a fine transport for a scan, but it is not an anonymised
one.

## Reproducing it

```bash
# 1. The target, pinned
git clone --depth 1 --branch dubbo-2.7.8 https://github.com/apache/dubbo.git

# 2. Reference set: OSV-Scanner, online, transitive resolution on (its default)
osv-scanner scan source -r ./dubbo --format json --output osv-online.json

# 3. OSV-Scanner with no network
osv-scanner scan source -r ./dubbo --offline --download-offline-databases \
  --format json --output osv-offline.json          # fetches its local DB once
unshare -rn osv-scanner scan source -r ./dubbo --offline \
  --format json --output osv-airgap.json           # real air gap

# 4. vigievuln: one online run to warm the cache, then no network
vigievuln -s ./dubbo --report-json fad-online.json
unshare -rn vigievuln -s ./dubbo --offline --report-json fad-airgap.json

# 5. Snyk at full capability — it invokes mvn, so this also populates ~/.m2
cd dubbo && snyk test --all-projects --json > ../snyk.json; cd ..

# 6. Trivy at full capability. With ~/.m2 populated by step 5 this equals the online
#    result exactly (559 raw pairs either way), which is worth verifying yourself.
trivy fs --scanners vuln --offline-scan --format json --output trivy-full.json ./dubbo
trivy fs --scanners vuln --format json --output trivy-online.json ./dubbo

# 7. Grype + Syft at full capability. Syft's transitive option is scoped to ARCHIVES, so on
#    a pom.xml source tree it is a no-op — the result does not move, 58 pairs either way.
grype dir:./dubbo -o json --file grype.json
SYFT_JAVA_RESOLVE_TRANSITIVE_DEPENDENCIES=true SYFT_JAVA_USE_NETWORK=true \
  syft dir:./dubbo -o syft-json=s.json && grype sbom:./s.json -o json --file grype-full.json
```

**If Maven Central rate-limits you** (`429 Too Many Requests`), and running several of these
back to back will, point Trivy at a mirror instead of waiting it out. Trivy reads
`settings.xml`, honours `<mirrors>`, and `MAVEN_HOME` keeps it out of your real Maven config:

```bash
mkdir -p /tmp/mvnhome/conf && cat > /tmp/mvnhome/conf/settings.xml <<'XML'
<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0">
  <localRepository>${user.home}/.m2/repository</localRepository>
  <mirrors><mirror>
    <id>gcs-central</id><mirrorOf>central</mirrorOf>
    <url>https://maven-central.storage-download.googleapis.com/maven2</url>
  </mirror></mirrors>
</settings>
XML
MAVEN_HOME=/tmp/mvnhome trivy fs --scanners vuln --format json -o trivy-online.json ./dubbo
```

That is how the online Trivy row here was obtained: the benchmark IP had been rate-limited by
the other scans, the penalty renewed on every retry, and the mirror is a different host serving
identical artifacts.

Compare on `(coordinate@version | vulnerability id)` pairs, restricted to Maven. Normalise two
things or the comparison is meaningless: map OSV `GHSA-*` ids to their `CVE-*` alias, and strip
Maven hard-pin brackets (`[1.2.3]` → `1.2.3`).

Environment for the numbers above: Node 24.14.0, Linux 6.6.87 (WSL2), vigievuln 2.4.6,
OSV-Scanner 2.4.0 (osv-scalibr 0.4.5).

## What vigievuln misses, and why

**At full capability: 118 pairs**, all found by Snyk and by no other tool.

> **Re-measured — 2026-09-18. Of 131 claimed misses, zero are recall bugs against OSV.**
>
> The analysis below read OSV's `affected[].versions` as a list of *fixed* versions. It is the
> list of **affected** versions ("each string is a single affected version", [osv-schema](https://github.com/ossf/osv-schema/blob/main/docs/schema.md)).
> It also read the CVE-converted record without its GHSA alias, where the Maven binding actually
> lives. Both errors inflate the gap.
>
> The run was repeated on the same pinned commit (fad 2.4.9, Snyk 1.1302.1, same method: distinct
> Maven `(coordinate@version | vulnerability)` pairs, reactor artifacts excluded). Snyk produced
> 654 distinct pairs, fad 873, and **131** Snyk pairs had no counterpart in fad. Each was
> adjudicated against OSV by `scripts/adjudicate-gap.js`:
>
> | | | |
> | ---: | --- | --- |
> | 57 | 43.5% | `WRONG_ARTIFACT` — the advisory binds a different coordinate |
> | 31 | 23.7% | `OUT_OF_RANGE` — the version is outside every declared affected range |
> | 23 | 17.6% | `NOT_IN_OSV` — 19 proprietary `SNYK-*` ids, 4 that only NVD carries |
> | 19 | 14.5% | `NO_MAVEN_BINDING` — the advisory binds no Maven package at all |
> | 1 | 0.8% | `ALREADY_REPORTED` — fad has it under the CVE alias |
> | **0** | **0.0%** | **`CONFIRMED_MISS`** |
>
> So **88 of the 131 (67%) are Snyk contradicting the public record**, and reporting them would
> mean shipping false positives. Two examples carry the whole argument. `GHSA-gm62-rw4g-vrc4` is
> claimed on `logback-classic@1.2.2`: it binds `logback-**core**` at `[1.2.12, 1.2.13)` — wrong
> artifact, and a version from before the flaw existed. `GHSA-72hv-8253-57qq` is claimed on
> `jackson-core@2.10.4` and `@2.5.2`: its ranges are `[2.15.0, 2.18.6)` and `[2.19.0, 2.21.1)`.
>
> **Independently reviewed**, adversarially, by a second model asked to find errors rather than
> agree. It re-queried all 131 pairs against OSV, fetched 20 advisories by id, and audited the
> range evaluation and the diff. Verdict: the zero holds. It also found three defects, all fixed
> above: `fetchVuln` discarded OSV's 404 alias hint (`"…but the following aliases were: GHSA-…"`),
> which mislabelled 4 public advisories as proprietary; the verdict was named `NO_PUBLIC_RECORD`
> when only OSV is queried; and the reviewer confirmed no bug in `rangeAffects` /
> `vulnAffectsVersion` that could *under*-count misses (multi-range advisories, `last_affected`,
> `introduced: "0"`, and Maven ordering on `.Final` / `.RELEASE` / `1.11 > 1.9` / `2.9.9 < 2.9.9.1`
> all check out), and that `mergeRecords` can only add bindings, so it cannot mask a miss.
>
> Three caveats it raised, kept here rather than buried. **`NOT_IN_OSV` is not "in no public
> database"** — 4 of the 23 (`CVE-2026-59281/59282/59283/47886` on `spring-core@4.3.16`) are in
> NVD. **The single `ALREADY_REPORTED`** rests on OSV aliasing `CVE-2021-29441` and
> `CVE-2021-29442` together while NVD treats them as distinct; fad reports only the former on
> `nacos-common@1.3.1`. **The diff credits fad's CPE-filtered findings as "seen"**, which touches
> exactly 3 pairs — all out of range anyway, so no verdict depends on it.
>
> **One authority, named — and where that cuts against this document.** The adjudication is
> defined against **OSV**, because OSV is what vigievuln queries by default and the adjudicator
> reuses its own range evaluation. Under NVD's CPE ranges instead, 36 of the 131 would sit inside
> a vulnerable range — but 24 of those are the framework-vs-artifact granularity noise that
> [`--nvd-cpe-match` was measured at 12% precision for](#a-negative-result-nvd-cpe-ranges-as-a-matching-tier)
> (`netty:netty` landing on every netty sub-artifact, and so on), so NVD is not the better
> authority here, it is the noisier one.
>
> Five are not noise, and they are awkward: `jackson-databind@2.5.2` for `CVE-2020-11112`,
> `-11113`, `-11619`, `-14060` and `-14062`. GHSA declares only the 2.9.x branch; NVD's range
> includes 2.5.2 — and the section further down argues, **about this exact artifact**, that the
> narrower entry is "incomplete CPE curation, not a statement that 2.5.2 is safe." So this
> document has reasoned in both directions: NVD's wider range when defending fad's findings,
> OSV's narrower one when dismissing these five. Under the OSV-defined adjudication they are
> `OUT_OF_RANGE` and the zero stands; under the opt-in `--nvd-cpe-match` tier fad would report
> them. The honest statement is **"0 recall bugs against OSV"**, not "0 against all public data".
>
> The 30/88 split below is the original assertion, kept for the record. It is not a verified
> result, and **"they are real misses, not Snyk noise" does not hold**. Re-adjudicate before
> treating any claimed miss as a recall bug:
> `node scripts/adjudicate-gap.js --snyk snyk.json --found findings.json`.

- **30** carry a proprietary `SNYK-*` identifier with no public CVE alias. They exist in Snyk's
  commercial database and in no public one.
- **87** are public CVEs. Checked against NVD's own CPE ranges: 7 confirmed outright, 13 where
  NVD's range disagrees, 67 where NVD simply has no CPE naming that artifact.

Neither the 13 nor the 67 exonerate fad, and both were traced to their cause.

**The 67 "NVD is silent" cases were classified from the CVE record alone** — and the 2026-09-18
re-measurement above supersedes this whole section. The worked example
used to be `CVE-2023-6481` on `logback-classic@1.2.2`, described as a coverage gap because the
CVE entry carries no Maven binding — only a GIT commit range. Fetching its GHSA alias shows the
binding does exist: `ch.qos.logback:logback-core`, `{introduced: 1.2.12, fixed: 1.2.13}`. The
audited dependency is a *different artifact* at a version *below the introduction*, so nothing
was missed. Whether the other 66 survive the same check is an open question, and
`scripts/adjudicate-gap.js` is what answers it per pair.

**The 13 "NVD contradicts" cases are NVD contradicting itself.** Two sibling jackson-databind
deserialization CVEs published weeks apart:

| CVE | Ranges NVD declares |
| --- | --- |
| CVE-2020-9546 | `2.0.0–2.7.9.7`, `2.8.0–2.8.11.6`, `2.9.0–2.9.10.4` |
| CVE-2020-10672 | `2.9.0–2.9.10.4` only |

2.5.2 is affected by both or by neither. The narrower entry is incomplete CPE curation, not a
statement that 2.5.2 is safe.

So the honest summary of this gap: public advisory data declares ranges **per release branch**,
and old branches that never received a fix are frequently just absent — plus a long tail of
records with no ecosystem binding. A hand-curated commercial database fills that in. Aggregating
public sources, however carefully, does not reproduce it. `--nvd-cpe-match` was the attempt, and
[it fails on precision](#a-negative-result-nvd-cpe-ranges-as-a-matching-tier) for a reason worth
reading.

**With no network: nothing**, on this project — 657 of 657 against OSV-Scanner's online output.
That is recall against one tool's view in one scenario; the adjudication above is the
completeness answer.

## A negative result: NVD CPE ranges as a matching tier

Since NVD's ranges are broader than OSV's, using them to *match* rather than only to *filter*
should close part of the gap. It does not, and the reason generalises.

Implemented as `--nvd-cpe-match` (off by default), restricted to coordinates with an unambiguous
1:1 entry in `data/cpe-coord-map.json`, no name heuristics, and no new network path. Measured on
Dubbo: **76 new findings, 9 of them (12%) corroborated by Snyk**. Allowing the curated map's
deliberate 1:N entries was worse — 262 findings, 8% corroborated.

The cause is a granularity mismatch, not bad curation. CPE products are **framework**-level
(`spring_framework`, `netty`, `log4j`) while Maven coordinates are **artifact**-level, so
`CVE-2016-1000027` — a spring-web flaw — lands on spring-core, spring-beans and spring-context
alike, and `CVE-2019-20444` (netty-codec-http) lands on netty-common, netty-codec and
netty-handler. This is the same limitation that makes CPE-driven scanners noisy.

Worth noting against the earlier finding: Snyk succeeds here precisely because its assertions are
curated **per artifact**. The problem was never which database to read, it was the granularity of
what that database asserts. The flag ships as a triage aid ("what might I be missing?") with its
12% stated in the flag's own help text.

## Honest caveats

- **`--offline` needs a warmed cache.** These numbers come from a cache warmed by one prior
  online run on the same project. On a cold cache the air-gapped run legitimately finds nothing.
  That is the intended air-gapped workflow (`--export-cache` / `--import-cache`), not a trick,
  but it means "100% with no network" is not the same as "100% from a standing start".
- **The machine had a populated `~/.m2` (287 MB).** It does not affect either tool here
  (OSV-Scanner resolves via deps.dev or Maven Central, not the local repository), but Trivy and
  Syft *do* consult it, so a comparison including them must control for it.
- **One project, one shape.** Dubbo is a large flat reactor with heavy transitive depth. A
  project whose vulnerabilities are mostly in direct dependencies would narrow the gap sharply,
  because direct dependencies are exactly what an offline scanner still sees.
- **This measures recall against one reference, not correctness.** fad also reports ~90 pairs that
  are not in OSV-Scanner's online output at all, because it additionally matches against the
  CVEProject index and NVD. Those are not counted as wins here, and they are not independently
  validated by this benchmark.

