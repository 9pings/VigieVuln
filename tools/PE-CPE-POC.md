# Experimental PE-to-CPE research

The binary inventory extracts untrusted Windows PE VERSIONINFO strings locally and
includes them in `unmanaged[].binaryMetadata` in the findings JSON and the HTML
inventory. These strings are claims made by the file, not verified identities.
Extraction does not identify CVEs and does not require Windows or network access.

`pe-cpe-poc.py` is a separate research tool, not part of the production scan. It
requires Python 3 and `pefile`. It never executes the file. A CPE search sends the
search term to NVD; a CVE search sends the supplied CPE. Do not send confidential
product information without considering this disclosure.

```sh
python3 tools/pe-cpe-poc.py /path/to/curl.exe --search curl
python3 tools/pe-cpe-poc.py /path/to/curl.exe \
  --cpe 'cpe:2.3:a:haxx:curl:8.21.0:*:*:*:*:*:*:*'
```

The operator supplies the product query and CPE. The tool only discovers exact
normalized product-name candidates in the first NVD page; its truncation flag
must be checked. It cannot establish that the binary belongs to a candidate, that
its file and product versions mean the same thing, or that a vendor build lacks
backported fixes. A CPE query returns **candidate** CVEs, not validated findings:
the full configuration and platform context still need review. The tool is not
offline-capable when either query is selected, does not implement retry/rate-limit
handling, and is not wired into proxies, reports, CI gates, or CVE enrichment.

Before promoting this path to a production finding, validate candidate selection
on a labelled corpus of real binary builds, handle ambiguous/multiple identities,
version schemes and full NVD applicability (including unknown platform context),
preserve provenance and uncertainty, and implement the existing proxy, caching and
offline contracts. Absence from NVD or a hash source must not imply safety.
