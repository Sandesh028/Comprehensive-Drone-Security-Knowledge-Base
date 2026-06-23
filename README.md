# DroneSecKB

An open UAV cybersecurity platform: the OWASP Drone Top 10, a curated CVE
register fed live from the NVD API, a UAS-native attack taxonomy, defensive
controls, shippable detection signatures, and a research profile.

**Live:** https://drone-security-kb.smore2022.workers.dev
**Maintainer:** Sandesh More, credited on CVE-2023-49199 and CVE-2023-49200.

## Pages

The site builds into five prerendered pages that share one design system:

| Page | File | What it holds |
|------|------|---------------|
| Home | `index.html` | Hero radar scope, featured research, what-is-inside grid, live NVD feed |
| Knowledge Base | `knowledge.html` | OWASP Drone Top 10, attack taxonomy, detections |
| CVE Register | `cves.html` | Searchable register, curated plus NVD auto-ingested |
| Research | `research.html` | Credited CVE disclosures, methodology, publications |
| About | `about.html` | Bio, focus areas, skills, experience, contact |

## Architecture (why the numbers never drift)

Canonical content lives as versioned JSON in [`/data`](./data):

| File | Contents |
|------|----------|
| `meta.json` | Title, version, maintainer, citation |
| `profile.json` | About-page bio, skills, experience, contact |
| `research.json` | Methodology, publications, contributions |
| `cves.json` | Curated CVE register (your flagship entries) |
| `cves_auto.json` | NVD auto-ingested CVEs (machine generated) |
| `owasp.json` | OWASP Drone Top 10 |
| `attacks.json` | UAS tactics and techniques |
| `detections.json` | Detection rules |

`build.py` reads that JSON plus `_style.css` and `_script.js` and renders the
five static pages. There is no in-browser Babel and no runtime fetch, so:

- Every count is computed from the data at build time, so the badges and totals cannot disagree with the records.
- The full content ships in the HTML, so crawlers and link previews see it.
- Pages load instantly.

```bash
python3 build.py     # regenerate all pages from /data
```

To add a CVE by hand, edit `data/cves.json` and run `build.py`. To restyle,
edit `_style.css` and rebuild.

## Automation (NVD ingestion)

`fetch_cves.py` pulls drone and UAV CVEs from the NVD 2.0 API, normalizes each
(CVSS, CWE, product, references), and writes `data/cves_auto.json`. NVD
descriptions are stored verbatim and tagged `source: NVD`. `build.py` merges
curated plus auto records, and **curated entries always win** on an ID
collision, so your flagship teardowns are never overwritten.

`.github/workflows/update-cves.yml` runs the fetch plus build every 6 hours and
on demand. `.github/workflows/build.yml` rebuilds whenever data, the builder,
or the styles change.

It refreshes on the workflow schedule, so it is not real-time, and `meta.json`
says exactly that.

### Optional free NVD key

`fetch_cves.py` works with no key (6-second pacing, within the public limit).
A free key raises the limit. Add it as a repo secret named `NVD_API_KEY` under
Settings, Secrets and variables, Actions, and the script speeds to 2-second
pacing. The key stays in the secret and never touches the code.

### NVD Terms of Use

The footer carries the required notice: "This product uses the NVD API but is
not endorsed or certified by the NVD." NVD content is shown verbatim, and
access stays within the posted rate limits.

## Deploy (Cloudflare Pages)

Static site. Point Cloudflare Pages at the repo root, build command
`python3 build.py`, output directory `/`.

## License

MIT. Educational use and authorized testing only.
