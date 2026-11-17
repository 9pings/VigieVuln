# Source resilience — 5 November 2026

The deployed source is identified by [receipt](deployment.json) and
[source manifest](source-manifest.json). [Validation](validation.json) records
2,302 passing CLI tests (11 skipped), 599 passing server tests, and an offline
NGINX replay with zero network attempts. Both public [health checks](health.json)
returned HTTP 200.

The client caps retries at 15, spaced at least three seconds apart, and respects
Retry-After within a shared 45-second scan wait budget by default. During terminal
waits, S or Escape stops further retries and restores the terminal input state.
Exhausting or skipping the budget does not prevent other resources from being read
from the proxy cache. A transport error after a retained cache response preserves
that response; explicit cancellation still propagates.
Individual record revalidation is typed, authenticated and subject to the same
upstream admission controls. Failed refreshes retain usable evidence with its
original timestamp; exact request identities prevent duplicate warnings.

Stable individual advisory reuse is enabled by default (unchanged for 365 days).
`--stable-advisory-age-days` changes the threshold, `--no-reuse-stable-advisories`
restores normal cache lifetimes, and `--force-update` overrides reuse. Queries that discover new advisories and dynamic KEV/EPSS signals are not
frozen. Proxy records retain their origin binding; unsupported or unknown dates
do not qualify for the shortcut.

The server mirrors metadata from the [official EUVD search API](https://euvd.enisa.europa.eu/apidoc).
It preserves the distinction between search metadata and detailed relationships.
The [observed initial progress](euvd-progress.json) is 29,909 records against a
reported catalogue total of 418,125: initial collection is **not complete**.
The worker continues bounded cycles automatically, then overlapping update windows
and periodic full traversals. Mutable pagination does not establish an atomic
snapshot or make a missing identifier a confirmed absence. Existing records are
served locally during bootstrap, with collection and check timestamps kept separate.

Rate-limit metadata also accompanies a retained HTTP 200 cache response when its
refresh was refused. Only identified admission or rate-limit causes trigger the
rate-limit retry path; an unknown stale response does not invent a quota. A bounded
wait retains a readable cached body and exposes the final refresh cause. Structured
headers and server logs contain source/status/cause/delay, never request credentials
or private package parameters.
