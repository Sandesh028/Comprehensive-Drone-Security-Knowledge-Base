# DroneSecKB — An Open UAV Cybersecurity Reference

A maintained reference for unmanned-aircraft-system (UAS) security: the OWASP
Drone Top 10, a curated CVE register, a **UAS-native attack taxonomy**, defensive
controls, and shippable **detection signatures**.

**Live:** https://drone-security-kb.smore2022.workers.dev
**Maintainer:** Sandesh More — credited on CVE-2023-49199 and CVE-2023-49200.

---

## What's in here

- **OWASP Drone Top 10** — ten risk classes, each with a real example, mitigations, and a link into the taxonomy.
- **CVE Register** — UAS vulnerabilities with CVSS, CWE, status, and mapping. The maintainer's own CVEs are flagged with ★.
- **UAS Attack Taxonomy** — a drone-native kill chain with domain-specific technique IDs (`UAS-RF / NAV / NET / FW / PHY`). Enterprise ATT&CK IDs appear only as *informational* cross-references, never as exact mappings.
- **Detection Signatures** — Suricata / Zeek / YARA content that detects the documented exposures.

## Architecture (why the numbers can't drift)

All content lives as canonical JSON in [`/data`](./data):

| File | Contents |
|------|----------|
| `meta.json` | Title, version, maintainer, citation |
| `cves.json` | The CVE register |
| `owasp.json` | OWASP Drone Top 10 |
| `attacks.json` | UAS tactics + techniques |
| `detections.json` | Detection rules |

`build.py` reads that JSON and renders a **fully prerendered static `index.html`** —
no in-browser Babel, no runtime `fetch`. That means:

- **Every count on the page is computed from the data at build time** (CVE totals, severity counts, technique counts). They cannot disagree with the records.
- The full content is in the served HTML, so **search engines and link previews see it** (the previous Babel-in-browser build was invisible to crawlers).
- The page loads instantly.

```bash
python3 build.py     # regenerates index.html from /data
```

To add a CVE: edit `data/cves.json`, run `build.py`, commit. The badge, the
dashboard counts, and the taxonomy chips all update from that one edit.

## Automation (NVD ingestion)

Drone/UAV CVEs are pulled from the **NVD 2.0 API** and merged into the register:

- `fetch_cves.py` sweeps a set of drone keywords (`drone`, `UAV`, `MAVLink`, `DJI`, `PX4`, …), normalizes each CVE (CVSS, CWE, product from CPE, references), and writes `data/cves_auto.json`. NVD descriptions are stored **verbatim** and tagged `source: "NVD"`.
- `build.py` merges curated + auto records. **Curated entries in `cves.json` always win** on an ID collision, so your flagship teardowns are never overwritten. Auto records render with an `NVD` tag.
- `.github/workflows/update-cves.yml` runs the fetch + build every 6 hours (and on demand), then commits `cves_auto.json` and `index.html`.

It refreshes on the workflow schedule — it is **not** real-time, and `meta.json` says so.

### Rate limits & the optional free key

`fetch_cves.py` works with **no key** (6-second pacing, within NVD's public limit).
A free key raises the limit; add it as a repo secret named `NVD_API_KEY`
(**Settings → Secrets and variables → Actions**) and the script picks it up and
speeds to 2-second pacing. The key lives only in the secret — never in code.

### NVD Terms of Use

The footer carries the required notice — *"This product uses the NVD API but is
not endorsed or certified by the NVD."* — NVD content is shown verbatim (not
modified while attributed to NVD), and access stays within the posted rate limits.

```bash
python3 fetch_cves.py   # refresh data/cves_auto.json from NVD
python3 build.py        # regenerate index.html from all data
```

## Deploy (Cloudflare Pages)

This is a static site — point Cloudflare Pages at the repo root, build command
`python3 build.py`, output directory `/` (or leave build empty and commit the
generated `index.html`).

## Cite

See `meta.json → citation` for the BibTeX entry. Archive a release on Zenodo to
get a DOI, then drop it into the citation.

## License

MIT. Educational use and **authorized testing only.**
