#!/usr/bin/env python3
"""
fetch_cves.py — pull drone/UAV CVEs from the NVD 2.0 API into data/cves_auto.json.

Design / compliance notes:
  * Works with NO key (public rate limit: 5 req / 30s -> 6s delay).
    If env var NVD_API_KEY is set, the key is sent in the header and the
    delay drops to 2s (NVD's recommended pace for keyed requests).
  * NVD descriptions are stored VERBATIM and tagged source="NVD". We never
    modify NVD content while attributing it to NVD (ToU requirement).
  * Curated records in data/cves.json are NOT written here and always win
    at build time, so your flagship CVE teardowns are never overwritten.
  * Standard library only — no pip install needed in CI.

Run:  python3 fetch_cves.py
Tune: env KEYWORDS="drone,UAV" to limit the sweep (comma separated).
"""
import json
import os
import pathlib
import re
import sys
import time
import urllib.parse
import urllib.request

API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DATA = pathlib.Path(__file__).parent / "data"
OUT = DATA / "cves_auto.json"

# Drone/UAV keyword sweep. Each keyword is a separate request (NVD treats
# multiple words in one query as AND, so we OR across the domain by looping).
DEFAULT_KEYWORDS = [
    "drone", "UAV", "UAS", "quadcopter", "MAVLink",
    "DroneID", "Remote ID drone", "DJI", "ArduPilot", "PX4",
]
KEYWORDS = [k.strip() for k in os.environ.get("KEYWORDS", ",".join(DEFAULT_KEYWORDS)).split(",") if k.strip()]

API_KEY = os.environ.get("NVD_API_KEY", "").strip()
DELAY = 2.0 if API_KEY else 6.0          # NVD-recommended pacing
PER_PAGE = 2000                           # NVD max/default
SEV = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}


def get(params):
    """One GET with retry/backoff; returns parsed JSON or None."""
    url = API + "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={"User-Agent": "DroneSecKB/2.0"})
    if API_KEY:
        req.add_header("apiKey", API_KEY)
    for attempt in range(4):
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.loads(r.read().decode())
        except Exception as ex:                      # noqa: BLE001
            wait = 6 * (attempt + 1)
            print(f"  retry in {wait}s ({ex})", file=sys.stderr)
            time.sleep(wait)
    return None


def cvss_of(metrics):
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key)
        if arr:
            d = arr[0]["cvssData"]
            sev = d.get("baseSeverity") or arr[0].get("baseSeverity") or ""
            return d.get("baseScore"), d.get("vectorString", ""), SEV.get(sev.upper(), "")
    return None, "", ""


def cwe_of(weaknesses):
    for w in weaknesses or []:
        for d in w.get("description", []):
            m = re.match(r"CWE-\d+", d.get("value", ""))
            if m:
                return m.group(0)
    return "—"


def product_of(configurations):
    for cfg in configurations or []:
        for node in cfg.get("nodes", []):
            for cpe in node.get("cpeMatch", []):
                if cpe.get("vulnerable") and cpe.get("criteria"):
                    parts = cpe["criteria"].split(":")
                    if len(parts) > 5:
                        vendor, product = parts[3], parts[4]
                        return f"{vendor} {product}".replace("_", " ").strip()
    return "See NVD"


def normalize(item):
    cve = item["cve"]
    desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    score, vector, sev = cvss_of(cve.get("metrics", {}))
    refs = [r["url"] for r in cve.get("references", [])][:4]
    if not any("nvd.nist.gov" in u for u in refs):
        refs.insert(0, f"https://nvd.nist.gov/vuln/detail/{cve['id']}")
    return {
        "id": cve["id"],
        "auto": True,
        "source": "NVD",
        "discoveredBy": "NVD",
        "title": (desc[:90] + "…") if len(desc) > 90 else desc,
        "severity": sev or "medium",
        "cvss": score if score is not None else "—",
        "cvssVector": vector,
        "cwe": cwe_of(cve.get("weaknesses")),
        "product": product_of(cve.get("configurations")),
        "status": cve.get("vulnStatus", "—"),
        "discovered": (cve.get("published", "") or "")[:10],
        "description": desc,                 # verbatim NVD content
        "owaspMapping": [],
        "taxonomyMapping": [],
        "references": refs,
    }


def main():
    found = {}
    print(f"NVD sweep · {len(KEYWORDS)} keywords · {'keyed' if API_KEY else 'keyless'} ({DELAY}s pacing)")
    for kw in KEYWORDS:
        start, total = 0, None
        while total is None or start < total:
            data = get({"keywordSearch": kw, "resultsPerPage": PER_PAGE, "startIndex": start, "noRejected": ""})
            if not data:
                break
            total = data.get("totalResults", 0)
            vulns = data.get("vulnerabilities", [])
            for v in vulns:
                rec = normalize(v)
                found[rec["id"]] = rec       # dedupe across keywords
            start += len(vulns)
            print(f"  {kw}: {start}/{total}")
            time.sleep(DELAY)
            if not vulns:
                break

    records = sorted(found.values(), key=lambda r: r["id"], reverse=True)
    OUT.write_text(json.dumps(records, indent=2))
    print(f"Wrote {len(records)} CVEs -> {OUT.relative_to(OUT.parent.parent)}")


if __name__ == "__main__":
    main()
