# Windows PE/CPE correlation experiment

Observed 2026-11-01 using the local Windows `System32/curl.exe` and the NVD API.
This is one exploratory case, not an estimate of detection precision or recall.

The binary declares ProductVersion and FileVersion 8.21.0, CompanyName
`curl, https://curl.se/`, and ProductName `The curl executable`. The NVD CPE
search `curl` returned separate `haxx:curl` and `curl_project:curl` candidates;
neither vendor string matches the metadata exactly. Selection of `haxx:curl` was
manual and does not prove the publisher or identity of this build.

For `cpe:2.3:a:haxx:curl:8.21.0:*:*:*:*:*:*:*`, the NVD CPE query returned nine
candidate CVEs, including CVE-2026-13608. The NVD range for this CVE includes
7.82.0 through versions before 8.22.0. The [curl advisory](https://curl.se/docs/CVE-2026-13608.html)
confirms those broad boundaries but states that the vulnerability requires the
OpenLDAP backend. Static PE imports include Windows `WLDAP32.dll`; this observation
does not establish which backend or dynamically loaded components the build uses.
Thus the CVE is a candidate, not a confirmed finding for this specific executable.

The NVD CPE query for the hypothetical version 8.20.1 also returns CVE-2026-13608.
The upstream advisory states that the separately maintained Rock-solid curl
8.20.1 build is fixed. A generic product/version range can therefore incorrectly
flag that specific variant. This test used a manually supplied version, not a
local 8.20.1 executable.

For hypothetical version 8.22.0 the CPE query returned zero records, although
the [upstream advisory for CVE-2026-92391](https://curl.se/docs/CVE-2026-92391.html)
identifies libcurl 8.22.0 as affected. The NVD record existed but had no CPE
configurations and was `Awaiting Analysis` when checked. Crucially the vendor says
this vulnerability does **not** affect the curl command-line tool. This illustrates
both incomplete CPE coverage and why product-level version matches cannot be
automatically attributed to every component. This was a CPE query, not a test of
an actual 8.22.0 Windows executable.

Consequences for implementation: retain raw metadata and every candidate, compare
component and build evidence, use CVE Project/OSV alongside NVD where appropriate,
and represent conditions or source coverage that cannot be resolved as unknown.
Neither an empty query nor a match alone establishes whether a build is safe.
