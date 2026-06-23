#!/usr/bin/env python3
"""
DroneSecKB multi-page static site builder.

Reads canonical JSON in /data and renders five prerendered pages that share
one design system: index.html, knowledge.html, cves.html, research.html,
about.html. All counts are computed from the data. NVD auto-ingested CVEs are
merged in (curated entries always win). Output is plain HTML + vanilla JS, so
crawlers see everything and pages load instantly.

Run:  python3 build.py
"""
import html
import json
import math
import pathlib

ROOT = pathlib.Path(__file__).parent
DATA = ROOT / "data"


def load(name):
    return json.loads((DATA / name).read_text())


meta = load("meta.json")
profile = load("profile.json")
research = load("research.json")
curated = load("cves.json")
owasp = load("owasp.json")
attacks = load("attacks.json")
detections = load("detections.json")
_auto_path = DATA / "cves_auto.json"
_auto = json.loads(_auto_path.read_text()) if _auto_path.exists() else []
_cur_ids = {c["id"] for c in curated}
auto_cves = [a for a in _auto if a["id"] not in _cur_ids]
cves = curated + auto_cves

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SEV_LABEL = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW"}


def e(x):
    return html.escape(str(x))


def fv(v, fb=""):
    """Graceful fallback for unfilled FILL_ME data."""
    s = "" if v is None else str(v)
    return fb if (s.startswith("FILL_ME") or s == "") else v


def is_fill(v):
    return ("" if v is None else str(v)).startswith("FILL_ME")


def sev_class(s):
    return "sev-" + str(s).lower() if s and str(s).lower() in SEV_ORDER else "sev-na"


def sev_pill(s):
    return f'<span class="sev-pill {sev_class(s)}">{SEV_LABEL.get(str(s).lower(), "n/a")}</span>'


# ----- computed stats -----
sev_counts = {k: 0 for k in SEV_ORDER}
for c in cves:
    s = str(c.get("severity", "")).lower()
    if s in sev_counts:
        sev_counts[s] += 1
S = {
    "cves": len(cves), "owasp": len(owasp), "techniques": len(attacks["techniques"]),
    "tactics": len(attacks["tactics"]), "detections": len(detections),
    "credited": len([c for c in curated if c.get("flagship")]),
    "auto": len(auto_cves), "critical": sev_counts["critical"], "high": sev_counts["high"],
}

ICONS = {
    "rf": '<path d="M5 12a7 7 0 0 1 7-7M5 12a7 7 0 0 0 7 7M2 12a10 10 0 0 1 10-10M2 12a10 10 0 0 0 10 10" fill="none"/><circle cx="12" cy="12" r="1.6"/>',
    "chip": '<rect x="6" y="6" width="12" height="12" rx="1" fill="none"/><path d="M9 3v3M15 3v3M9 18v3M15 18v3M3 9h3M3 15h3M18 9h3M18 15h3" fill="none"/>',
    "net": '<circle cx="12" cy="5" r="2" fill="none"/><circle cx="5" cy="19" r="2" fill="none"/><circle cx="19" cy="19" r="2" fill="none"/><path d="M12 7v4M12 11l-6 6M12 11l6 6" fill="none"/>',
    "shield": '<path d="M12 3l7 3v6c0 4-3 7-7 9-4-2-7-5-7-9V6z" fill="none"/><path d="M9 12l2 2 4-4" fill="none"/>',
}


def icon(name):
    return (f'<svg class="ic" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.5" '
            f'fill="currentColor" aria-hidden="true">{ICONS.get(name, "")}</svg>')


# ================= shared chrome =================
NAV = [("index.html", "Home"), ("knowledge.html", "Knowledge Base"),
       ("cves.html", "CVE Register"), ("research.html", "Research"), ("about.html", "About")]


def header(active):
    items = []
    for href, label in NAV:
        cls = ' class="active"' if href == active else ""
        items.append(f'<a href="{href}"{cls}>{e(label)}</a>')
    links = "".join(items)
    return f"""<header class="topbar">
  <a class="brand" href="index.html"><span class="logo" aria-hidden="true">&#9670;</span>{e(meta['title'])}<span class="ver">v{e(meta['version'])}</span></a>
  <button class="menu-btn" aria-label="Menu" aria-expanded="false">&#9776;</button>
  <nav class="nav">{links}</nav>
  <a class="ghbtn" href="{e(meta['repo_url'])}" target="_blank" rel="noopener">GitHub &#8599;</a>
</header>"""


def footer():
    return f"""<footer class="foot">
  <div class="foot-row">
    <span>{e(meta['title'])} v{e(meta['version'])} &middot; built {e(meta['lastUpdated'])}</span>
    <span>Data: <a href="{e(meta['repo_url'])}" target="_blank" rel="noopener">/data on GitHub</a> &middot; educational use, authorized testing only</span>
  </div>
  <p class="nvd-attr">This product uses the NVD API but is not endorsed or certified by the NVD.</p>
</footer>"""


def page(title, desc, active, body):
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{e(title)}</title>
<meta name="description" content="{e(desc)}">
<meta property="og:title" content="{e(title)}">
<meta property="og:description" content="{e(desc)}">
<meta property="og:type" content="website">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=Inter:wght@400;500;600&family=IBM+Plex+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>{CSS}</style>
</head>
<body>
<div class="scanline" aria-hidden="true"></div>
{header(active)}
<main>{body}</main>
{footer()}
<script>{JS}</script>
</body>
</html>"""


# ================= reusable components =================
def page_head(eyebrow, title, sub):
    return f"""<section class="phead reveal">
  <p class="eyebrow">{e(eyebrow)}</p>
  <h1>{e(title)}</h1>
  <p class="phead-sub">{e(sub)}</p>
</section>"""


def cve_card(c):
    flag = ' <span class="own" title="Credited to the maintainer">&#9733; OWN</span>' if c.get("flagship") else ""
    nvd = ' <span class="nvdtag" title="Auto-ingested from the NVD API">NVD</span>' if c.get("auto") else ""
    refs = "".join(f'<a href="{e(u)}" target="_blank" rel="noopener">ref</a>'
                   for u in c.get("references", []) if not str(u).startswith("FILL"))
    desc = fv(c.get("description"), "Teardown detail coming soon.")
    title = fv(c.get("title"), "")
    return f"""<article class="card cve {sev_class(c.get('severity'))}"{' data-fill="1"' if c.get('flagship') else ''}
      data-sev="{e(str(c.get('severity','')).lower())}" data-q="{e((c['id']+' '+str(title)+' '+str(c.get('product','')).lower()))}">
      <div class="cve-head"><h3>{e(c['id'])}{flag}{nvd}</h3>{sev_pill(c.get('severity'))}</div>
      <p class="cve-title">{e(title)}</p>
      <dl class="cve-meta">
        <div><dt>CVSS</dt><dd>{e(fv(c.get('cvss'),'n/a'))}</dd></div>
        <div><dt>CWE</dt><dd>{e(fv(c.get('cwe'),'n/a'))}</dd></div>
        <div><dt>PRODUCT</dt><dd>{e(fv(c.get('product'),'n/a'))}</dd></div>
        <div><dt>STATUS</dt><dd>{e(fv(c.get('status'),'n/a'))}</dd></div>
      </dl>
      <p class="cve-desc">{e(desc)}</p>
      <div class="cve-foot"><span class="by">{e(fv(c.get('discoveredBy'),'n/a'))}</span><span class="refs">{refs}</span></div>
    </article>"""


def owasp_cards():
    out = ""
    for r in owasp:
        mits = "".join(f"<li>{e(m)}</li>" for m in r["mitigations"])
        tax = "".join(f'<a class="tag" href="knowledge.html#taxonomy">{e(t)}</a>' for t in r.get("taxonomyMapping", []))
        out += f"""<article class="card owasp {sev_class(r['severity'])}" data-sev="{e(str(r['severity']).lower())}">
      <header class="card-top"><span class="rank">D{r['rank']:02d}</span>{sev_pill(r['severity'])}</header>
      <h3>{e(r['title'])}</h3>
      <p class="proto">{e(r['protocol'])}</p>
      <p class="desc">{e(r['description'])}</p>
      <p class="example"><span class="lbl">SEEN IN</span> {e(r['realExample'])}</p>
      <details><summary>Mitigations &amp; mapping</summary><ul class="mits">{mits}</ul><div class="tags">{tax}</div></details>
      <div class="cvss-bar"><span style="width:{min(r['cvss'],10)/10*100:.0f}%"></span><b>{r['cvss']}</b></div>
    </article>"""
    return out


def matrix():
    by = {t["id"]: [] for t in attacks["tactics"]}
    for tech in attacks["techniques"]:
        by.setdefault(tech["tacticId"], []).append(tech)
    cols = ""
    for t in sorted(attacks["tactics"], key=lambda x: x["phase"]):
        cells = ""
        for tech in by.get(t["id"], []):
            chips = "".join(f'<span class="mini">{e(x)}</span>' for x in tech.get("relatedCves", []) if not str(x).startswith("FILL"))
            cells += f"""<div class="cell {sev_class(tech['severity'])}">
          <span class="tid">{e(tech['id'])}</span><span class="tname">{e(tech['name'])}</span>
          <span class="tsum">{e(tech['summary'])}</span><span class="tcves">{chips}</span></div>"""
        cols += f"""<div class="col"><div class="col-head"><span class="ph">{t['phase']:02d}</span><span>{e(t['name'])}</span></div>{cells}</div>"""
    return cols


def det_cards():
    out = ""
    for d in detections:
        tax = "".join(f'<span class="tag">{e(x)}</span>' for x in d.get("relatedTaxonomy", []))
        out += f"""<article class="card det reveal">
      <header class="det-head"><span class="engine">{e(d['engine'])}</span><span class="det-tactic">{e(d['tactic'])}</span></header>
      <h3>{e(d['name'])}</h3><p class="desc">{e(d['summary'])}</p>
      <pre><code>{e(d['rule'])}</code></pre><div class="tags">{tax}</div></article>"""
    return out


def radar_svg():
    R = {"critical": 0.30, "high": 0.50, "medium": 0.70, "low": 0.88}
    n = len(owasp)
    blips = ""
    for i, r in enumerate(owasp):
        ang = (-90 + (360.0 / n) * i) * math.pi / 180.0
        rad = R.get(str(r["severity"]).lower(), 0.6)
        cx, cy = 50 + math.cos(ang) * rad * 46, 50 + math.sin(ang) * rad * 46
        blips += (f'<g class="blip {sev_class(r["severity"])}" style="--d:{i*0.12}s" transform="translate({cx:.1f},{cy:.1f})">'
                  f'<circle r="1.6"/><circle class="ping" r="1.6"/><text x="3" y="1" class="blip-label">{e(r["id"])}</text></g>')
    rings = "".join(f'<circle cx="50" cy="50" r="{r}" class="ring{" outer" if r==48 else ""}"/>' for r in (48, 36, 24, 12))
    return f"""<svg viewBox="0 0 100 100" role="img">
      <defs><radialGradient id="g" cx="50%" cy="50%" r="50%"><stop offset="0%" stop-color="var(--scope)" stop-opacity=".18"/><stop offset="100%" stop-color="var(--scope)" stop-opacity="0"/></radialGradient></defs>
      {rings}<line x1="50" y1="2" x2="50" y2="98" class="cross"/><line x1="2" y1="50" x2="98" y2="50" class="cross"/>
      <circle cx="50" cy="50" r="48" fill="url(#g)"/><g class="sweep"><path d="M50 50 L50 2 A48 48 0 0 1 86 22 Z"/></g>{blips}</svg>"""


# ================= page bodies =================
def home_body():
    feat = [c for c in curated if c.get("flagship")][:2]
    feat_html = "".join(f"""<a class="feat-cve {sev_class(fv(c.get('severity'),'medium'))}" href="research.html">
        <div class="feat-top"><span class="cid">{e(c['id'])}</span><span class="own">&#9733; OWN</span></div>
        <p class="feat-t">{e(fv(c.get('title'),'Coordinated disclosure, teardown on the research page'))}</p>
        <span class="feat-link">Read the teardown &#8594;</span></a>""" for c in feat)
    recent = sorted(auto_cves, key=lambda r: r["id"], reverse=True)[:4]
    recent_html = "".join(f"""<a class="nvd-row {sev_class(c.get('severity'))}" href="cves.html">
        <span class="nr-id">{e(c['id'])}</span>{sev_pill(c.get('severity'))}
        <span class="nr-prod">{e(fv(c.get('product'),'see NVD'))}</span></a>""" for c in recent) or '<p class="muted">Run the NVD workflow to populate the latest CVEs.</p>'
    bento = [
        ("knowledge.html", "OWASP Drone Top 10", S["owasp"], "risk classes", "The ten ways UAS get owned, each with a real example and fixes."),
        ("knowledge.html#taxonomy", "Attack Taxonomy", S["techniques"], "techniques", "A drone-native kill chain with UAS-specific technique IDs."),
        ("cves.html", "CVE Register", S["cves"], "records", "A searchable register, auto-fed from the NVD API."),
        ("knowledge.html#detections", "Detections", S["detections"], "signatures", "Suricata, Zeek, and YARA content defenders can ship."),
    ]
    bento_html = "".join(f"""<a class="bento {('span2' if i==0 else '')}" href="{href}">
        <div class="bento-n"><b data-count="{num}">0</b><span>{lbl}</span></div>
        <h3>{e(t)}</h3><p>{e(d)}</p><span class="bento-go">Open &#8594;</span></a>""" for i, (href, t, num, lbl, d) in enumerate(bento))
    return f"""
<section class="hero">
  <div class="hero-grid">
    <div class="hero-copy reveal">
      <p class="eyebrow">UNMANNED-AIRCRAFT-SYSTEM SECURITY &middot; MAINTAINED REFERENCE</p>
      <h1>The airspace has<br>an attack surface.</h1>
      <p class="lede">{e(meta['description'])}</p>
      <div class="hero-stats">
        <div class="stat"><b data-count="{S['cves']}">0</b><span>CVEs tracked</span></div>
        <div class="stat"><b data-count="{S['techniques']}">0</b><span>UAS techniques</span></div>
        <div class="stat"><b data-count="{S['owasp']}">0</b><span>OWASP risks</span></div>
        <div class="stat"><b data-count="{S['detections']}">0</b><span>Detection rules</span></div>
      </div>
      <p class="own-line">&#9733; Includes <b>{S['credited']}</b> CVEs credited to the maintainer, with teardown detail published nowhere else.</p>
      <div class="hero-cta"><a class="btn primary" href="knowledge.html">Explore the knowledge base</a><a class="btn ghost" href="research.html">View the research</a></div>
    </div>
    <figure class="scope reveal" aria-label="Threat scope: OWASP Drone Top 10 by severity, center is most critical">
      {radar_svg()}<figcaption>OWASP Drone Top 10 &middot; proximity to center encodes severity</figcaption>
    </figure>
  </div>
</section>

<section class="band reveal">
  <div class="band-head"><p class="eyebrow">FEATURED RESEARCH</p><h2>Vulnerabilities I found</h2></div>
  <div class="feat-grid">{feat_html}</div>
</section>

<section class="band reveal">
  <div class="band-head"><p class="eyebrow">WHAT IS INSIDE</p><h2>One reference, four surfaces</h2></div>
  <div class="bento-grid">{bento_html}</div>
</section>

<section class="band reveal">
  <div class="band-head split"><div><p class="eyebrow">LIVE FROM NVD</p><h2>Newest in the register</h2></div><a class="btn ghost sm" href="cves.html">See all {S['cves']} &#8594;</a></div>
  <div class="nvd-list">{recent_html}</div>
  <p class="muted tiny">Auto-ingested from the National Vulnerability Database on a schedule. This product uses the NVD API but is not endorsed or certified by the NVD.</p>
</section>

<section class="band about-teaser reveal">
  <div><p class="eyebrow">THE RESEARCHER</p><h2>{e(fv(profile.get('headline'),'About the maintainer'))}</h2>
  <p class="lede sm">{e(profile['bio_short'])}</p>
  <a class="btn primary" href="about.html">Get to know me</a></div>
</section>"""


def knowledge_body():
    return f"""
{page_head("REFERENCE", "Knowledge Base", "The OWASP Drone Top 10, a UAS-native attack taxonomy, and shippable detections. Everything here is built from versioned data, so the counts never drift.")}
<nav class="subnav"><a href="#owasp">OWASP Top 10</a><a href="#taxonomy">Attack Taxonomy</a><a href="#detections">Detections</a></nav>

<section id="owasp" class="block">
  <div class="block-head"><p class="eyebrow">FRAMEWORK &middot; {S['owasp']} RISKS</p><h2>OWASP Drone Top 10</h2>
  <p class="sub">Ten risk classes for UAS, each with a real example, mitigations, and a link into the taxonomy. Filter by severity.</p>
  <div class="filters" data-target="owasp"><button class="chip active" data-sev="all">All</button><button class="chip" data-sev="critical">Critical</button><button class="chip" data-sev="high">High</button><button class="chip" data-sev="medium">Medium</button><button class="chip" data-sev="low">Low</button></div></div>
  <div class="grid owasp-grid" id="owasp-grid">{owasp_cards()}</div>
</section>

<section id="taxonomy" class="block">
  <div class="block-head"><p class="eyebrow">{S['tactics']} TACTICS &middot; {S['techniques']} TECHNIQUES</p><h2>UAS Attack Taxonomy</h2>
  <p class="sub">A drone-native kill chain with domain-specific technique IDs (UAS-RF / NAV / NET / FW / PHY). Enterprise ATT&amp;CK analogs live inside each technique as informational cross-references only, not exact mappings.</p></div>
  <div class="matrix">{matrix()}</div>
</section>

<section id="detections" class="block">
  <div class="block-head"><p class="eyebrow">DEFENDER CONTENT &middot; {S['detections']} SIGNATURES</p><h2>Detection Signatures</h2>
  <p class="sub">Shippable Suricata, Zeek, and YARA content that detects the documented exposures. Tune SIDs and thresholds for your environment.</p></div>
  <div class="grid det-grid">{det_cards()}</div>
</section>"""


def cves_body():
    rows = "".join(cve_card(c) for c in sorted(cves, key=lambda x: SEV_ORDER.get(str(x.get("severity", "")).lower(), 9)))
    return f"""
{page_head(f"{S['cves']} RECORDS \u00b7 {S['critical']} CRITICAL \u00b7 {S['high']} HIGH \u00b7 {S['auto']} VIA NVD", "CVE Register", "Curated UAS vulnerabilities with CVSS, CWE, and mapping. Records auto-ingested from the NVD API are tagged NVD; entries credited to the maintainer are marked with a star.")}
<section class="block pt0">
  <div class="cve-controls">
    <input id="cve-search" type="search" placeholder="Search CVE, product, vendor..." aria-label="Search CVEs">
    <div class="filters" data-target="cve"><button class="chip active" data-sev="all">All</button><button class="chip" data-sev="critical">Critical</button><button class="chip" data-sev="high">High</button><button class="chip" data-sev="medium">Medium</button><button class="chip" data-sev="low">Low</button></div>
  </div>
  <div class="grid cve-grid" id="cve-grid">{rows}</div>
  <p class="empty" id="cve-empty" hidden>No records match that filter.</p>
</section>"""


def research_body():
    feat = [c for c in curated if c.get("flagship")]
    feat_html = ""
    for c in feat:
        tech = fv(c.get("technicalDetails"), "")
        tech_block = f'<div class="teardown"><span class="lbl">TEARDOWN</span><p>{e(tech)}</p></div>' if tech else '<div class="teardown pending"><span class="lbl">TEARDOWN</span><p>Full technical teardown is being prepared.</p></div>'
        refs = "".join(f'<a href="{e(u)}" target="_blank" rel="noopener">{e(u.replace("https://","").replace("http://","")[:55])}</a>' for u in c.get("references", []) if not str(u).startswith("FILL"))
        feat_html += f"""<article class="rcve {sev_class(fv(c.get('severity'),'medium'))} reveal">
      <header class="rcve-head"><div><span class="cid">{e(c['id'])}</span> <span class="own">&#9733; CREDITED TO ME</span></div>{sev_pill(fv(c.get('severity'),'medium'))}</header>
      <h3>{e(fv(c.get('title'),'Title pending publication'))}</h3>
      <dl class="cve-meta wide"><div><dt>CVSS</dt><dd>{e(fv(c.get('cvss'),'n/a'))}</dd></div><div><dt>CWE</dt><dd>{e(fv(c.get('cwe'),'n/a'))}</dd></div><div><dt>PRODUCT</dt><dd>{e(fv(c.get('product'),'n/a'))}</dd></div><div><dt>STATUS</dt><dd>{e(fv(c.get('status'),'n/a'))}</dd></div></dl>
      <p class="rcve-desc">{e(fv(c.get('description'),'Coordinated disclosure. Public summary is being finalized.'))}</p>
      {tech_block}
      <div class="rcve-refs">{refs}</div></article>"""
    method = "".join(f"""<div class="mstep reveal"><span class="ms-n">{m['step']:02d}</span><div><h4>{e(m['name'])}</h4><p>{e(m['detail'])}</p></div></div>""" for m in research["methodology"])
    pubs = [p for p in research.get("publications", []) if not is_fill(p.get("title"))]
    pubs_html = "".join(f"""<li class="pub"><div><span class="pub-t">{e(p['title'])}</span><span class="pub-v">{e(fv(p.get('venue'),''))} &middot; {e(fv(p.get('year'),''))}</span></div>{f'<a href="{e(p["url"])}" target="_blank" rel="noopener">link &#8599;</a>' if not is_fill(p.get('url')) else ''}</li>""" for p in pubs) or '<li class="muted">Publications will be listed here.</li>'
    contribs = [c for c in research.get("contributions", []) if not is_fill(c)]
    contribs_html = "".join(f"<li>{e(c)}</li>" for c in contribs) or '<li class="muted">Open-source and community contributions will be listed here.</li>'
    return f"""
{page_head("RESEARCH AND DISCLOSURES", "Research", fv(research.get('intro'),'Original UAS research and coordinated disclosures.'))}
<section class="block pt0">
  <div class="block-head"><p class="eyebrow">CREDITED CVES &middot; {S['credited']}</p><h2>Disclosures</h2></div>
  <div class="rcve-grid">{feat_html}</div>
</section>
<section class="block">
  <div class="block-head"><p class="eyebrow">HOW I WORK</p><h2>Methodology</h2></div>
  <div class="methodology">{method}</div>
</section>
<section class="block">
  <div class="two-col">
    <div><div class="block-head"><p class="eyebrow">WRITING</p><h2>Publications</h2></div><ul class="pub-list">{pubs_html}</ul></div>
    <div><div class="block-head"><p class="eyebrow">COMMUNITY</p><h2>Contributions</h2></div><ul class="contrib-list">{contribs_html}</ul></div>
  </div>
</section>"""


def about_body():
    foci = "".join(f"""<article class="focus reveal"><span class="focus-ic">{icon(f.get('icon',''))}</span><h3>{e(f['name'])}</h3><p>{e(f['summary'])}</p></article>""" for f in profile["focus_areas"])
    skills = "".join(f"""<div class="skillgroup reveal"><h4>{e(g['group'])}</h4><div class="chips">{''.join(f'<span class="schip">{e(i)}</span>' for i in g['items'])}</div></div>""" for g in profile["skills"])
    exp = [x for x in profile.get("experience", []) if not is_fill(x.get("role"))]
    exp_html = "".join(f"""<div class="tl-item reveal"><div class="tl-dot"></div><div class="tl-body"><div class="tl-top"><span class="tl-role">{e(x['role'])}</span><span class="tl-period">{e(fv(x.get('period'),''))}</span></div><span class="tl-org">{e(fv(x.get('org'),''))}</span><ul>{''.join(f'<li>{e(p)}</li>' for p in x.get('points',[]) if not is_fill(p))}</ul></div></div>""" for x in exp) or '<p class="muted">Experience timeline is being finalized.</p>'
    edu = [x for x in profile.get("education", []) if not is_fill(x.get("degree"))]
    edu_html = "".join(f"""<div class="edu reveal"><span class="edu-d">{e(x['degree'])}</span><span class="edu-s">{e(fv(x.get('school'),''))} &middot; {e(fv(x.get('period'),''))}</span></div>""" for x in edu) or '<p class="muted">Education details coming soon.</p>'
    c = profile["contact"]
    links = []
    for label, key, pre in [("Email", "email", "mailto:"), ("GitHub", "github", ""), ("Portfolio", "portfolio", ""), ("LinkedIn", "linkedin", ""), ("ORCID", "orcid", "https://orcid.org/")]:
        val = c.get(key)
        if not is_fill(val):
            href = pre + val
            links.append(f'<a class="contact-link" href="{e(href)}" target="_blank" rel="noopener">{label} &#8599;</a>')
    contact_html = "".join(links) or '<p class="muted">Contact links coming soon.</p>'
    bio = fv(profile.get("bio_long"), profile["bio_short"])
    return f"""
{page_head("THE RESEARCHER", "About " + e(meta['maintainer']['name']), fv(profile.get('available_for') and ('Open to ' + profile['available_for']), ''))}
<section class="block pt0">
  <div class="bio-grid">
    <div class="bio reveal"><p class="bio-lead">{e(fv(profile.get('headline'),''))}</p><p>{e(bio)}</p></div>
    <aside class="bio-side reveal">
      <div class="bio-stat"><b>{S['credited']}</b><span>CVEs credited</span></div>
      <div class="bio-stat"><b>{S['cves']}</b><span>CVEs catalogued</span></div>
      <div class="bio-stat"><b>{S['detections']}</b><span>detections shipped</span></div>
      <div class="contacts">{contact_html}</div>
    </aside>
  </div>
</section>
<section class="block"><div class="block-head"><p class="eyebrow">WHERE I FOCUS</p><h2>Focus areas</h2></div><div class="focus-grid">{foci}</div></section>
<section class="block"><div class="block-head"><p class="eyebrow">TOOLKIT</p><h2>Skills</h2></div><div class="skills-grid">{skills}</div></section>
<section class="block"><div class="block-head"><p class="eyebrow">PATH</p><h2>Experience</h2></div><div class="timeline">{exp_html}</div></section>
<section class="block"><div class="block-head"><p class="eyebrow">STUDY</p><h2>Education</h2></div><div class="edu-list">{edu_html}</div></section>"""


# ================= CSS / JS =================
CSS = (DATA.parent / "_style.css").read_text() if (DATA.parent / "_style.css").exists() else ""
JS = (DATA.parent / "_script.js").read_text() if (DATA.parent / "_script.js").exists() else ""

# ================= write pages =================
pages = {
    "index.html": page(f"{meta['title']} \u00b7 {meta['tagline']}", meta["description"], "index.html", home_body()),
    "knowledge.html": page(f"Knowledge Base \u00b7 {meta['title']}", "OWASP Drone Top 10, UAS attack taxonomy, and shippable detection signatures.", "knowledge.html", knowledge_body()),
    "cves.html": page(f"CVE Register \u00b7 {meta['title']}", "Searchable UAS CVE register, auto-fed from the NVD API.", "cves.html", cves_body()),
    "research.html": page(f"Research \u00b7 {meta['title']}", "Credited CVE disclosures and UAS security research.", "research.html", research_body()),
    "about.html": page(f"About \u00b7 {meta['maintainer']['name']}", profile["bio_short"], "about.html", about_body()),
}
for name, content in pages.items():
    (ROOT / name).write_text(content)
print("Built", len(pages), "pages:", ", ".join(pages))
print(f"  {S['cves']} CVEs ({S['auto']} via NVD), {S['owasp']} OWASP, {S['techniques']} techniques, {S['detections']} detections")
