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

## Automation

> **TODO (maintainer):** describe the automation accurately in `meta.json → pipeline_note`.
> The earlier "real-time NVD ingestion" wording did not match a static artifact.
> If the GitHub Action below commits NVD results on a schedule, say so and link it.
> If the register is curated by hand, say that. Don't claim real-time ingestion the
> deployed site doesn't perform.

A starter workflow lives at [`.github/workflows/build.yml`](./.github/workflows/build.yml):
it rebuilds `index.html` on every push to `data/` so the site can never ship a
stale render.

## Deploy (Cloudflare Pages)

This is a static site — point Cloudflare Pages at the repo root, build command
`python3 build.py`, output directory `/` (or leave build empty and commit the
generated `index.html`).

## Cite

See `meta.json → citation` for the BibTeX entry. Archive a release on Zenodo to
get a DOI, then drop it into the citation.

## License

MIT. Educational use and **authorized testing only.**
