# Debian historical security evidence

Debian's current tracker can stop exposing release-specific status after a release
reaches end of support. The historical adapter can consult an immutable commit of
Debian's security tracker from the end of that release's support. It reads
`data/CVE/list`, `data/DSA/list` and `data/DLA/list`, preserving the commit, cutoff,
source digests and observation times. The release cutoff is selected from a lifecycle
observation and checked against the installed Debian version and codename. The
historical assessment is additional to the current advisory sources; it does not
replace them and it cannot cover vulnerabilities discovered after the cutoff.

Debian's tracker computes a package's release status from the unqualified source
package note and its version, then applies any release-specific override. The adapter
implements that order, including fixes linked through `DSA/list` and `DLA/list`.
`no-dsa`, `ignored` and `postponed` are triage annotations; they do not replace the
underlying version status. The comparison uses the installed **source package** version
and Debian's ordering. A threshold inherited from an unqualified note is evidence for
the verdict, not a proposed release-specific fix; only an explicit release fix is
reported as such. Missing source versions, unresolved tracker statuses and unsupported
releases remain indeterminate. Debian's `unimportant` urgency remains attributed
tracker context on an affected finding; it is not a version verdict or an inferred
CVSS score.

As with the ordinary OSV system adapter, a package finding is conditional on the
identity reported by installed package metadata. Matching a Debian-like name and
version does not authenticate installed bytes. Explicit third-party origin produces a
separate possible observation instead of a Debian affected verdict. Optional positive
corroboration against [Debian Sources](https://sources.debian.org/) records that the
exact source version appears in the release; an absent result does not prove that a
package is third-party, because that service need not retain every security version.

A relay keeps the full upstream tracker snapshots and returns only whole advisory
blocks for requested source packages. The local snapshot records that package scope;
packages never consulted do not inherit a clean result. The SQLite cache and scoped
observations transfer in the standard cache archive and remain usable offline.

For an unsupported release, a separate optional consultation pins a newer tracker
commit and evaluates its current source-package notes against installed source
versions. These results are **possible observations**, not confirmed release
findings: a generic current fix or an unaffected status for another release does
not establish what happened in the unsupported release. Each observation retains
the comparison, release context, tracker commit and historical cutoff. The current
dataset has a separate package-scoped cache and a four-hour default refresh period;
offline scans retain its actual observation time. Fleet and hosted consultations
request only the relevant package projection, and the cache can be transferred.

The independent Freexian tracker adds release-scoped source-package assessments.
Reconciliation requires the same distribution, source and installed version, binary
occurrence and CVE. A proven non-affected or fixed assessment updates the corresponding
candidate observation, retaining both sources' evidence. Conflicting findings from
another source remain visible and receive an explicit conflict observation; absent,
ambiguous, third-party or differently scoped evidence cannot settle a candidate.
Tracker archive status is evaluated against the actual installed source version;
an unrelated release or a newer archive package cannot establish its status.
When the archive verdict is indeterminate, an optional bounded second pass checks
the corresponding Freexian CVE page for an exact source-package and release row.
An explicit release-level non-affected row or an installed version at or above a
release-specific fixed version can refine that observation. Page evidence is cached
per CVE for offline replay; missing, ambiguous or differently scoped rows remain
indeterminate. The pass is limited to existing Debian current candidates, with a
default budget of 1,000 distinct CVEs and three pages in flight; both are configurable.

Primary references: [Debian Security Tracker format and release semantics](https://security-team.debian.org/security_tracker.html),
[Debian 11 LTS end-of-life announcement](https://www.debian.org/News/2026/20260831),
and [Debian security tracker repository](https://salsa.debian.org/security-tracker-team/security-tracker).

The 6 November NGINX replay and its tuple-level Freexian assessments are recorded
in the [ELTS evidence](benchmark-evidence/2026-11-06-images/elts/README.md). A
release-qualified negative assessment remains visible and is not counted as a
confirmed vulnerability; unresolved release applicability remains explicit.
