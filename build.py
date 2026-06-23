#!/usr/bin/env python3
"""
DroneSecKB static site builder.

Reads the canonical JSON in /data and renders a single, fully prerendered
index.html. All visible counts are computed here from the data, so they
cannot drift. Output is plain HTML + vanilla JS (no Babel, no runtime
fetch), which means crawlers see the full content and the page loads
instantly.

Usage:  python3 build.py
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
cves = load("cves.json")
# Merge NVD auto-ingested CVEs (if present). Curated entries always win.
_auto_path = DATA / "cves_auto.json"
_auto = json.loads(_auto_path.read_text()) if _auto_path.exists() else []
_curated_ids = {c["id"] for c in cves}
auto_cves = [a for a in _auto if a["id"] not in _curated_ids]
cves = cves + auto_cves
owasp = load("owasp.json")
attacks = load("attacks.json")
detections = load("detections.json")

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SEV_LABEL = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW"}


def e(x):
    return html.escape(str(x))


def sev_class(s):
    return "sev-" + str(s).lower() if s and str(s).lower() in SEV_ORDER else "sev-na"


# ---------- computed stats (single source of truth) ----------
sev_counts = {k: 0 for k in SEV_ORDER}
for c in cves:
    s = str(c.get("severity", "")).lower()
    if s in sev_counts:
        sev_counts[s] += 1

stats = {
    "cves": len(cves),
    "owasp": len(owasp),
    "techniques": len(attacks["techniques"]),
    "tactics": len(attacks["tactics"]),
    "detections": len(detections),
    "credited": len([c for c in cves if c.get("flagship")]),
    "auto": len([c for c in cves if c.get("auto")]),
    "critical": sev_counts["critical"],
    "high": sev_counts["high"],
}

# ---------- radar blips: OWASP risks plotted on the threat scope ----------
# severity -> radius fraction (critical closest to center = highest threat)
RADIUS = {"critical": 0.30, "high": 0.50, "medium": 0.70, "low": 0.88}
blips = []
n = len(owasp)
for i, r in enumerate(owasp):
    ang = (-90 + (360.0 / n) * i) * math.pi / 180.0
    rad = RADIUS.get(str(r["severity"]).lower(), 0.6)
    cx, cy = 50 + math.cos(ang) * rad * 46, 50 + math.sin(ang) * rad * 46
    blips.append((cx, cy, r["severity"], r["id"], r["title"]))

blip_svg = "".join(
    f'<g class="blip {sev_class(s)}" style="--d:{i*0.12}s" transform="translate({cx:.1f},{cy:.1f})">'
    f'<circle r="1.6"/><circle class="ping" r="1.6"/>'
    f'<text x="3" y="1" class="blip-label">{e(bid)}</text></g>'
    for i, (cx, cy, s, bid, _t) in enumerate(blips)
)

# ---------- OWASP cards ----------
owasp_cards = ""
for r in owasp:
    mits = "".join(f"<li>{e(m)}</li>" for m in r["mitigations"])
    tax = "".join(f'<a class="tag" href="#taxonomy">{e(t)}</a>' for t in r.get("taxonomyMapping", []))
    owasp_cards += f"""
    <article class="card owasp {sev_class(r['severity'])}" data-sev="{e(str(r['severity']).lower())}">
      <header class="card-top">
        <span class="rank">D{r['rank']:02d}</span>
        <span class="sev-pill {sev_class(r['severity'])}">{SEV_LABEL[str(r['severity']).lower()]}</span>
      </header>
      <h3>{e(r['title'])}</h3>
      <p class="proto">{e(r['protocol'])}</p>
      <p class="desc">{e(r['description'])}</p>
      <p class="example"><span class="lbl">SEEN IN</span> {e(r['realExample'])}</p>
      <details>
        <summary>Mitigations &amp; mapping</summary>
        <ul class="mits">{mits}</ul>
        <div class="tags">{tax}</div>
      </details>
      <div class="cvss-bar"><span style="width:{min(r['cvss'],10)/10*100:.0f}%"></span><b>{r['cvss']}</b></div>
    </article>"""

# ---------- CVE rows ----------
cve_rows = ""
for c in sorted(cves, key=lambda x: SEV_ORDER.get(str(x.get("severity", "")).lower(), 9)):
    flag = ' <span class="own" title="Discovered by the maintainer">★ OWN</span>' if c.get("flagship") else ""
    nvd = ' <span class="nvdtag" title="Auto-ingested from the NVD API">NVD</span>' if c.get("auto") else ""
    fill = ' data-fill="1"' if c.get("flagship") else ""
    refs = "".join(
        f'<a href="{e(u)}" target="_blank" rel="noopener">ref</a>'
        for u in c.get("references", []) if not str(u).startswith("FILL")
    )
    cve_rows += f"""
    <article class="card cve {sev_class(c.get('severity'))}"{fill}
      data-sev="{e(str(c.get('severity','')).lower())}" data-q="{e((c['id']+' '+str(c.get('title',''))+' '+str(c.get('product',''))).lower())}">
      <div class="cve-head">
        <h3>{e(c['id'])}{flag}{nvd}</h3>
        <span class="sev-pill {sev_class(c.get('severity'))}">{SEV_LABEL.get(str(c.get('severity','')).lower(),'—')}</span>
      </div>
      <p class="cve-title">{e(c.get('title',''))}</p>
      <dl class="cve-meta">
        <div><dt>CVSS</dt><dd>{e(c.get('cvss','—'))}</dd></div>
        <div><dt>CWE</dt><dd>{e(c.get('cwe','—'))}</dd></div>
        <div><dt>PRODUCT</dt><dd>{e(c.get('product','—'))}</dd></div>
        <div><dt>STATUS</dt><dd>{e(c.get('status','—'))}</dd></div>
      </dl>
      <p class="cve-desc">{e(c.get('description',''))}</p>
      <div class="cve-foot"><span class="by">{e(c.get('discoveredBy','—'))}</span><span class="refs">{refs}</span></div>
    </article>"""

# ---------- attack taxonomy: kill-chain columns ----------
tech_by_tactic = {t["id"]: [] for t in attacks["tactics"]}
for tech in attacks["techniques"]:
    tech_by_tactic.setdefault(tech["tacticId"], []).append(tech)

matrix_cols = ""
for t in sorted(attacks["tactics"], key=lambda x: x["phase"]):
    cells = ""
    for tech in tech_by_tactic.get(t["id"], []):
        cves_for = "".join(f'<span class="mini">{e(x)}</span>' for x in tech.get("relatedCves", []) if not str(x).startswith("FILL"))
        cells += f"""
        <div class="cell {sev_class(tech['severity'])}" data-sev="{e(tech['severity'])}">
          <span class="tid">{e(tech['id'])}</span>
          <span class="tname">{e(tech['name'])}</span>
          <span class="tsum">{e(tech['summary'])}</span>
          <span class="tcves">{cves_for}</span>
        </div>"""
    matrix_cols += f"""
    <div class="col">
      <div class="col-head"><span class="ph">{t['phase']:02d}</span><span>{e(t['name'])}</span></div>
      {cells}
    </div>"""

# ---------- detections ----------
det_cards = ""
for d in detections:
    tax = "".join(f'<span class="tag">{e(x)}</span>' for x in d.get("relatedTaxonomy", []))
    det_cards += f"""
    <article class="card det">
      <header class="det-head"><span class="engine">{e(d['engine'])}</span><span class="det-tactic">{e(d['tactic'])}</span></header>
      <h3>{e(d['name'])}</h3>
      <p class="desc">{e(d['summary'])}</p>
      <pre><code>{e(d['rule'])}</code></pre>
      <div class="tags">{tax}</div>
    </article>"""

m = meta["maintainer"]
portfolio = m["portfolio_url"].replace("FILL_ME: ", "")
orcid = m["orcid"].replace("FILL_ME: ", "")

CSS = r"""
:root{
  --void:#070B14; --panel:#0C1322; --panel-2:#101a2e; --grid:#1B2942;
  --ink:#E7EEFA; --muted:#8A9BB5; --faint:#5d6f8c;
  --scope:#34E5C4; --scope-dim:rgba(52,229,196,.10);
  --critical:#FF5C72; --high:#FF9F45; --medium:#FFD23F; --low:#58C7F3; --na:#5d6f8c;
  --disp:'Space Grotesk',system-ui,sans-serif;
  --body:'Inter',system-ui,sans-serif;
  --mono:'IBM Plex Mono',ui-monospace,monospace;
  --maxw:1180px;
}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{
  margin:0;background:var(--void);color:var(--ink);font-family:var(--body);
  line-height:1.6;-webkit-font-smoothing:antialiased;
  background-image:radial-gradient(900px 500px at 78% -8%,rgba(52,229,196,.07),transparent 60%),
                   radial-gradient(700px 600px at 0% 100%,rgba(88,199,243,.05),transparent 55%);
}
a{color:inherit;text-decoration:none}
h1,h2,h3{font-family:var(--disp);font-weight:700;letter-spacing:-.02em;line-height:1.05;margin:0}
.eyebrow{font-family:var(--mono);font-size:.7rem;letter-spacing:.22em;color:var(--scope);
  text-transform:uppercase;margin:0 0 .9rem}
.scanline{position:fixed;inset:0;pointer-events:none;z-index:200;mix-blend-mode:overlay;opacity:.5;
  background:repeating-linear-gradient(0deg,rgba(255,255,255,.018) 0 1px,transparent 1px 3px)}

/* topbar */
.topbar{position:sticky;top:0;z-index:100;display:flex;align-items:center;gap:1.4rem;
  padding:.85rem clamp(1rem,4vw,2.4rem);
  background:rgba(7,11,20,.78);backdrop-filter:blur(14px);
  border-bottom:1px solid var(--grid)}
.brand{font-family:var(--disp);font-weight:700;font-size:1.05rem;letter-spacing:-.01em;display:flex;align-items:center;gap:.5rem}
.brand .logo{color:var(--scope);font-size:.85rem;letter-spacing:-.15em}
.brand .ver{font-family:var(--mono);font-size:.62rem;color:var(--faint);padding:.1rem .4rem;border:1px solid var(--grid);border-radius:4px;margin-left:.3rem}
.nav{display:flex;gap:.2rem;margin-left:auto;flex-wrap:wrap}
.nav a{font-family:var(--mono);font-size:.74rem;letter-spacing:.04em;color:var(--muted);
  padding:.45rem .7rem;border-radius:6px;transition:.18s}
.nav a:hover{color:var(--ink);background:var(--panel)}
.nav a.active{color:var(--scope)}
.ghbtn{font-family:var(--mono);font-size:.74rem;color:var(--void);background:var(--scope);
  padding:.5rem .85rem;border-radius:6px;font-weight:600;transition:.18s}
.ghbtn:hover{filter:brightness(1.1);transform:translateY(-1px)}

main{max-width:var(--maxw);margin:0 auto;padding:0 clamp(1rem,4vw,2.4rem)}

/* hero */
.hero{padding:clamp(3rem,8vw,6rem) 0 clamp(2rem,5vw,4rem)}
.hero-grid{display:grid;grid-template-columns:1.05fr .95fr;gap:clamp(1.5rem,4vw,3.5rem);align-items:center}
.hero h1{font-size:clamp(2.6rem,6.5vw,5rem);margin:.2rem 0 1.2rem}
.lede{font-size:1.06rem;color:var(--muted);max-width:46ch;margin:0 0 2rem}
.hero-stats{display:grid;grid-template-columns:repeat(4,auto);gap:clamp(1rem,3vw,2.4rem);margin-bottom:1.6rem}
.stat b{font-family:var(--mono);font-size:clamp(1.7rem,4vw,2.5rem);font-weight:600;color:var(--ink);display:block;line-height:1}
.stat span{font-family:var(--mono);font-size:.66rem;letter-spacing:.1em;text-transform:uppercase;color:var(--faint)}
.own-line{font-size:.92rem;color:var(--muted);border-left:2px solid var(--scope);padding-left:.9rem;margin:0 0 2rem}
.own-line b{color:var(--scope)}
.hero-cta{display:flex;gap:.8rem;flex-wrap:wrap}
.btn{font-family:var(--mono);font-size:.8rem;padding:.7rem 1.2rem;border-radius:7px;transition:.18s;border:1px solid transparent}
.btn.primary{background:var(--scope);color:var(--void);font-weight:600}
.btn.primary:hover{filter:brightness(1.1);transform:translateY(-1px)}
.btn.ghost{border-color:var(--grid);color:var(--ink)}
.btn.ghost:hover{border-color:var(--scope);color:var(--scope)}

/* radar scope (signature) */
.scope{margin:0;position:relative}
.scope svg{width:100%;height:auto;display:block;filter:drop-shadow(0 0 40px rgba(52,229,196,.18))}
.ring{fill:none;stroke:var(--grid);stroke-width:.3}
.ring.outer{stroke:var(--scope);stroke-opacity:.4;stroke-width:.4}
.cross{stroke:var(--grid);stroke-width:.2}
.sweep{transform-origin:50px 50px;animation:sweep 4.4s linear infinite}
.sweep path{fill:var(--scope);opacity:.16}
.blip circle{fill:var(--na)}
.blip .ping{fill:none;stroke:currentColor;stroke-width:.5;transform-origin:center;animation:ping 2.6s ease-out infinite;animation-delay:var(--d)}
.blip.sev-critical{color:var(--critical)} .blip.sev-critical circle:first-child{fill:var(--critical)}
.blip.sev-high{color:var(--high)} .blip.sev-high circle:first-child{fill:var(--high)}
.blip.sev-medium{color:var(--medium)} .blip.sev-medium circle:first-child{fill:var(--medium)}
.blip.sev-low{color:var(--low)} .blip.sev-low circle:first-child{fill:var(--low)}
.blip-label{font-family:var(--mono);font-size:2.4px;fill:var(--muted)}
.scope figcaption{font-family:var(--mono);font-size:.64rem;letter-spacing:.08em;color:var(--faint);text-align:center;margin-top:.8rem;text-transform:uppercase}
@keyframes sweep{to{transform:rotate(360deg)}}
@keyframes ping{0%{transform:scale(1);opacity:.9}80%,100%{transform:scale(4.5);opacity:0}}

/* blocks */
.block{padding:clamp(2.6rem,6vw,4.5rem) 0;border-top:1px solid var(--grid)}
.block-head{margin-bottom:2rem;max-width:62ch}
.block-head h2{font-size:clamp(1.8rem,4vw,2.7rem);margin-bottom:.7rem}
.sub{color:var(--muted);font-size:.98rem;margin:0}

/* filters */
.filters{display:flex;gap:.4rem;flex-wrap:wrap;margin-top:1.1rem}
.chip{font-family:var(--mono);font-size:.72rem;color:var(--muted);background:transparent;
  border:1px solid var(--grid);padding:.4rem .8rem;border-radius:20px;cursor:pointer;transition:.16s}
.chip:hover{border-color:var(--scope);color:var(--ink)}
.chip.active{background:var(--scope);color:var(--void);border-color:var(--scope);font-weight:600}

/* grids + cards */
.grid{display:grid;gap:1rem}
.owasp-grid{grid-template-columns:repeat(auto-fill,minmax(290px,1fr))}
.cve-grid{grid-template-columns:repeat(auto-fill,minmax(320px,1fr))}
.det-grid{grid-template-columns:repeat(auto-fill,minmax(360px,1fr))}
.card{background:linear-gradient(180deg,var(--panel),var(--panel-2));border:1px solid var(--grid);
  border-radius:12px;padding:1.25rem;position:relative;overflow:hidden;transition:.2s}
.card::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--na)}
.card.sev-critical::before{background:var(--critical)} .card.sev-high::before{background:var(--high)}
.card.sev-medium::before{background:var(--medium)} .card.sev-low::before{background:var(--low)}
.card:hover{transform:translateY(-3px);border-color:#26405f;box-shadow:0 18px 40px -22px rgba(0,0,0,.8)}
.card h3{font-size:1.12rem;margin-bottom:.3rem}
.card .desc{color:var(--muted);font-size:.9rem;margin:.5rem 0}
.sev-pill{font-family:var(--mono);font-size:.6rem;letter-spacing:.12em;padding:.22rem .5rem;border-radius:4px;
  font-weight:600;white-space:nowrap}
.sev-critical .sev-pill,.sev-pill.sev-critical{background:rgba(255,92,114,.16);color:var(--critical)}
.sev-high .sev-pill,.sev-pill.sev-high{background:rgba(255,159,69,.16);color:var(--high)}
.sev-medium .sev-pill,.sev-pill.sev-medium{background:rgba(255,210,63,.16);color:var(--medium)}
.sev-low .sev-pill,.sev-pill.sev-low{background:rgba(88,199,243,.16);color:var(--low)}
.sev-pill.sev-na{background:rgba(93,111,140,.16);color:var(--na)}

/* owasp card */
.card-top{display:flex;justify-content:space-between;align-items:center;margin-bottom:.7rem}
.rank{font-family:var(--mono);font-size:.95rem;font-weight:600;color:var(--scope)}
.proto{font-family:var(--mono);font-size:.7rem;color:var(--faint);text-transform:uppercase;letter-spacing:.06em;margin:.2rem 0 .5rem}
.example{font-size:.82rem;color:var(--muted);background:rgba(255,255,255,.02);border:1px solid var(--grid);
  border-radius:7px;padding:.6rem .7rem;margin:.6rem 0}
.example .lbl{font-family:var(--mono);font-size:.58rem;letter-spacing:.14em;color:var(--scope);display:block;margin-bottom:.2rem}
details summary{font-family:var(--mono);font-size:.72rem;color:var(--scope);cursor:pointer;padding:.3rem 0}
.mits{margin:.4rem 0;padding-left:1.1rem;font-size:.82rem;color:var(--muted)}
.mits li{margin:.15rem 0}
.tags{display:flex;gap:.35rem;flex-wrap:wrap;margin-top:.5rem}
.tag,.mini{font-family:var(--mono);font-size:.62rem;color:var(--low);border:1px solid var(--grid);
  padding:.18rem .45rem;border-radius:5px}
.cvss-bar{display:flex;align-items:center;gap:.5rem;margin-top:.9rem}
.cvss-bar>span{height:5px;background:linear-gradient(90deg,var(--scope),var(--high));border-radius:3px;flex:0 0 auto;max-width:calc(100% - 3rem)}
.cvss-bar b{font-family:var(--mono);font-size:.78rem;margin-left:auto;flex:0 0 auto}

/* cve card */
.cve-head{display:flex;justify-content:space-between;align-items:center}
.cve .own{font-family:var(--mono);font-size:.58rem;color:var(--scope);border:1px solid var(--scope);
  padding:.1rem .35rem;border-radius:4px;vertical-align:middle;margin-left:.3rem}
.nvdtag{font-family:var(--mono);font-size:.56rem;color:var(--low);border:1px solid var(--low);
  padding:.08rem .3rem;border-radius:4px;vertical-align:middle;margin-left:.3rem;letter-spacing:.06em}
.nvd-attr{color:var(--faint);font-style:italic;width:100%;border-top:1px solid var(--grid);padding-top:.7rem;margin-top:.3rem}
.cve[data-fill="1"]{box-shadow:inset 0 0 0 1px rgba(52,229,196,.35)}
.cve-title{font-size:.9rem;color:var(--ink);margin:.35rem 0 .7rem}
.cve-meta{display:grid;grid-template-columns:1fr 1fr;gap:.4rem .9rem;margin:0 0 .7rem}
.cve-meta div{border-bottom:1px solid var(--grid);padding-bottom:.25rem}
.cve-meta dt{font-family:var(--mono);font-size:.56rem;letter-spacing:.1em;color:var(--faint)}
.cve-meta dd{margin:0;font-size:.82rem;font-family:var(--mono)}
.cve-desc{font-size:.84rem;color:var(--muted);margin:.2rem 0 .8rem}
.cve-foot{display:flex;justify-content:space-between;align-items:center;font-family:var(--mono);font-size:.68rem}
.cve-foot .by{color:var(--faint)}
.cve-foot .refs a{color:var(--low);margin-left:.5rem}
.cve-foot .refs a:hover{color:var(--scope)}
.cve-controls{display:flex;flex-wrap:wrap;gap:.8rem;align-items:center;margin-top:1.1rem}
#cve-search{font-family:var(--mono);font-size:.8rem;background:var(--panel);border:1px solid var(--grid);
  color:var(--ink);padding:.6rem .9rem;border-radius:8px;min-width:240px;flex:1}
#cve-search:focus{outline:none;border-color:var(--scope)}
.empty{font-family:var(--mono);color:var(--faint);text-align:center;padding:2rem}

/* matrix */
.matrix{display:flex;gap:.8rem;overflow-x:auto;padding-bottom:1rem}
.col{flex:1 0 200px;min-width:200px}
.col-head{display:flex;align-items:center;gap:.5rem;font-family:var(--disp);font-weight:600;font-size:.9rem;
  padding:.6rem .7rem;background:var(--panel);border:1px solid var(--grid);border-radius:8px;margin-bottom:.6rem}
.col-head .ph{font-family:var(--mono);font-size:.7rem;color:var(--scope)}
.cell{background:linear-gradient(180deg,var(--panel),var(--panel-2));border:1px solid var(--grid);
  border-left:3px solid var(--na);border-radius:8px;padding:.7rem;margin-bottom:.55rem;display:flex;flex-direction:column;gap:.25rem;transition:.16s}
.cell.sev-critical{border-left-color:var(--critical)} .cell.sev-high{border-left-color:var(--high)}
.cell.sev-medium{border-left-color:var(--medium)} .cell.sev-low{border-left-color:var(--low)}
.cell:hover{transform:translateX(2px);border-color:#26405f}
.cell .tid{font-family:var(--mono);font-size:.64rem;color:var(--scope);letter-spacing:.04em}
.cell .tname{font-weight:600;font-size:.9rem}
.cell .tsum{font-size:.78rem;color:var(--muted)}
.cell .tcves{display:flex;gap:.3rem;flex-wrap:wrap;margin-top:.2rem}

/* detections */
.det pre{background:#060a12;border:1px solid var(--grid);border-radius:8px;padding:.8rem;overflow-x:auto;margin:.6rem 0}
.det code{font-family:var(--mono);font-size:.72rem;color:#bfe9dd;white-space:pre}
.det-head{display:flex;justify-content:space-between;align-items:center;margin-bottom:.4rem}
.engine{font-family:var(--mono);font-size:.66rem;font-weight:600;color:var(--void);background:var(--scope);padding:.2rem .5rem;border-radius:4px}
.det-tactic{font-family:var(--mono);font-size:.66rem;color:var(--faint);letter-spacing:.06em;text-transform:uppercase}

/* about */
.about-grid{display:grid;grid-template-columns:1.2fr 1fr;gap:2rem}
.about p{color:var(--muted)}
.about b{color:var(--ink)}
.links{display:flex;gap:1.2rem;font-family:var(--mono);font-size:.82rem;margin:1rem 0}
.links a{color:var(--scope)}
.note{font-size:.82rem;border-left:2px solid var(--grid);padding-left:.9rem;margin:1rem 0}
.note.pipeline{border-left-color:var(--high)}
.cite pre{background:#060a12;border:1px solid var(--grid);border-radius:8px;padding:1rem;overflow-x:auto}
.cite code{font-family:var(--mono);font-size:.7rem;color:#9fb6d4;white-space:pre}

/* footer */
.foot{max-width:var(--maxw);margin:0 auto;padding:2rem clamp(1rem,4vw,2.4rem) 3rem;
  display:flex;justify-content:space-between;flex-wrap:wrap;gap:.6rem;border-top:1px solid var(--grid);
  font-family:var(--mono);font-size:.7rem;color:var(--faint)}
.foot a{color:var(--low)}

:focus-visible{outline:2px solid var(--scope);outline-offset:2px;border-radius:4px}

@media(max-width:860px){
  .hero-grid{grid-template-columns:1fr}
  .scope{max-width:380px;margin:0 auto;order:-1}
  .about-grid{grid-template-columns:1fr}
  .nav{display:none}
}
@media(max-width:480px){
  .hero-stats{grid-template-columns:repeat(2,1fr);gap:1.2rem}
  .cve-meta{grid-template-columns:1fr 1fr}
}
@media(prefers-reduced-motion:reduce){
  html{scroll-behavior:auto}
  .sweep,.blip .ping{animation:none}
  .sweep path{opacity:.1}
  *{transition:none!important}
}
"""

JS = r"""
// count-up stats
function countUp(el){
  const target=+el.dataset.count, dur=900, t0=performance.now();
  function step(t){const p=Math.min((t-t0)/dur,1);
    el.textContent=Math.round(target*(1-Math.pow(1-p,3)));
    if(p<1)requestAnimationFrame(step);}
  requestAnimationFrame(step);
}
const reduce=matchMedia('(prefers-reduced-motion:reduce)').matches;
document.querySelectorAll('.stat b[data-count]').forEach(el=>{
  if(reduce){el.textContent=el.dataset.count;}else{countUp(el);}
});

// severity filters (owasp + cve)
document.querySelectorAll('.filters').forEach(group=>{
  const target=group.dataset.target;
  group.addEventListener('click',e=>{
    const btn=e.target.closest('.chip'); if(!btn)return;
    group.querySelectorAll('.chip').forEach(c=>c.classList.remove('active'));
    btn.classList.add('active');
    applyFilters(target);
  });
});
const search=document.getElementById('cve-search');
if(search)search.addEventListener('input',()=>applyFilters('cve'));

function activeSev(target){
  const g=document.querySelector('.filters[data-target="'+target+'"] .chip.active');
  return g?g.dataset.sev:'all';
}
function applyFilters(target){
  if(target==='owasp'){
    const sev=activeSev('owasp');
    document.querySelectorAll('#owasp-grid .card').forEach(c=>{
      c.style.display=(sev==='all'||c.dataset.sev===sev)?'':'none';
    });
  }else{
    const sev=activeSev('cve'), q=(search?search.value:'').trim().toLowerCase();
    let shown=0;
    document.querySelectorAll('#cve-grid .card').forEach(c=>{
      const ok=(sev==='all'||c.dataset.sev===sev)&&(!q||c.dataset.q.includes(q));
      c.style.display=ok?'':'none'; if(ok)shown++;
    });
    const empty=document.getElementById('cve-empty'); if(empty)empty.hidden=shown>0;
  }
}

// nav active state on scroll
const links=[...document.querySelectorAll('.nav a')];
const obs=new IntersectionObserver(es=>{
  es.forEach(en=>{if(en.isIntersecting){
    links.forEach(l=>l.classList.toggle('active',l.getAttribute('href')==='#'+en.target.id));
  }});
},{rootMargin:'-45% 0px -50% 0px'});
document.querySelectorAll('main section[id]').forEach(s=>obs.observe(s));
"""

# ---------- assemble ----------
PAGE = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{e(meta['title'])} — {e(meta['tagline'])}</title>
<meta name="description" content="{e(meta['description'])}">
<meta property="og:title" content="{e(meta['title'])} — UAV Security Reference">
<meta property="og:description" content="{e(meta['description'])}">
<meta property="og:type" content="website">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=Inter:wght@400;500;600&family=IBM+Plex+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<script type="application/ld+json">
{{"@context":"https://schema.org","@type":"Dataset","name":"{e(meta['title'])}","description":"{e(meta['description'])}","url":"{e(meta['site_url'])}","creator":{{"@type":"Person","name":"{e(m['name'])}"}},"keywords":["UAV security","drone security","CVE","OWASP Drone Top 10","UAS"]}}
</script>
<style>{CSS}</style>
</head>
<body>
<div class="scanline" aria-hidden="true"></div>

<header class="topbar">
  <a class="brand" href="#overview"><span class="logo" aria-hidden="true">◢◤</span>{e(meta['title'])}<span class="ver">v{e(meta['version'])}</span></a>
  <nav class="nav">
    <a href="#overview" class="active">Overview</a>
    <a href="#owasp">OWASP&nbsp;10</a>
    <a href="#cves">CVE&nbsp;Register</a>
    <a href="#taxonomy">Attack&nbsp;Taxonomy</a>
    <a href="#detections">Detections</a>
    <a href="#about">About</a>
  </nav>
  <a class="ghbtn" href="{e(meta['repo_url'])}" target="_blank" rel="noopener">GitHub ↗</a>
</header>

<main>
<!-- OVERVIEW / HERO -->
<section id="overview" class="hero">
  <div class="hero-grid">
    <div class="hero-copy">
      <p class="eyebrow">UNMANNED-AIRCRAFT-SYSTEM SECURITY · MAINTAINED REFERENCE</p>
      <h1>The airspace has<br>an attack surface.</h1>
      <p class="lede">{e(meta['description'])}</p>
      <div class="hero-stats">
        <div class="stat"><b data-count="{stats['cves']}">0</b><span>CVEs tracked</span></div>
        <div class="stat"><b data-count="{stats['techniques']}">0</b><span>UAS techniques</span></div>
        <div class="stat"><b data-count="{stats['owasp']}">0</b><span>OWASP risks</span></div>
        <div class="stat"><b data-count="{stats['detections']}">0</b><span>Detection rules</span></div>
      </div>
      <p class="own-line">★ Includes <b>{stats['credited']}</b> CVEs credited to the maintainer, documented with teardown detail not published elsewhere.</p>
      <div class="hero-cta">
        <a class="btn primary" href="#cves">Browse the register</a>
        <a class="btn ghost" href="#taxonomy">View attack taxonomy</a>
      </div>
    </div>

    <figure class="scope" aria-label="Threat scope: OWASP Drone Top 10 plotted by severity (center = most critical)">
      <svg viewBox="0 0 100 100" role="img">
        <defs>
          <radialGradient id="g" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stop-color="var(--scope)" stop-opacity=".18"/>
            <stop offset="100%" stop-color="var(--scope)" stop-opacity="0"/>
          </radialGradient>
        </defs>
        <circle cx="50" cy="50" r="48" class="ring outer"/>
        <circle cx="50" cy="50" r="36" class="ring"/>
        <circle cx="50" cy="50" r="24" class="ring"/>
        <circle cx="50" cy="50" r="12" class="ring"/>
        <line x1="50" y1="2" x2="50" y2="98" class="cross"/>
        <line x1="2" y1="50" x2="98" y2="50" class="cross"/>
        <circle cx="50" cy="50" r="48" fill="url(#g)"/>
        <g class="sweep"><path d="M50 50 L50 2 A48 48 0 0 1 86 22 Z"/></g>
        {blip_svg}
      </svg>
      <figcaption>OWASP Drone Top 10 — proximity to center encodes severity</figcaption>
    </figure>
  </div>
</section>

<!-- OWASP -->
<section id="owasp" class="block">
  <div class="block-head">
    <p class="eyebrow">FRAMEWORK</p>
    <h2>OWASP Drone Top 10</h2>
    <p class="sub">The ten risk classes for UAS, each with a real-world example, mitigations, and a link into the attack taxonomy. Filter by severity.</p>
    <div class="filters" data-target="owasp">
      <button class="chip active" data-sev="all">All</button>
      <button class="chip" data-sev="critical">Critical</button>
      <button class="chip" data-sev="high">High</button>
      <button class="chip" data-sev="medium">Medium</button>
      <button class="chip" data-sev="low">Low</button>
    </div>
  </div>
  <div class="grid owasp-grid" id="owasp-grid">{owasp_cards}</div>
</section>

<!-- CVES -->
<section id="cves" class="block">
  <div class="block-head">
    <p class="eyebrow">{stats['cves']} RECORDS · {stats['critical']} CRITICAL · {stats['high']} HIGH{(' · ' + str(stats['auto']) + ' VIA NVD') if stats['auto'] else ''}</p>
    <h2>CVE Register</h2>
    <p class="sub">Curated UAS vulnerabilities with CVSS, CWE, and mapping. ★ marks entries credited to the maintainer; <span class="nvdtag">NVD</span> marks records auto-ingested from the National Vulnerability Database.</p>
    <div class="cve-controls">
      <input id="cve-search" type="search" placeholder="Search CVE, product, vendor…" aria-label="Search CVEs">
      <div class="filters" data-target="cve">
        <button class="chip active" data-sev="all">All</button>
        <button class="chip" data-sev="critical">Critical</button>
        <button class="chip" data-sev="high">High</button>
        <button class="chip" data-sev="medium">Medium</button>
        <button class="chip" data-sev="low">Low</button>
      </div>
    </div>
  </div>
  <div class="grid cve-grid" id="cve-grid">{cve_rows}</div>
  <p class="empty" id="cve-empty" hidden>No records match that filter.</p>
</section>

<!-- TAXONOMY -->
<section id="taxonomy" class="block">
  <div class="block-head">
    <p class="eyebrow">{stats['tactics']} TACTICS · {stats['techniques']} TECHNIQUES</p>
    <h2>UAS Attack Taxonomy</h2>
    <p class="sub">A drone-native kill chain with domain-specific technique IDs (UAS-RF / NAV / NET / FW / PHY). Enterprise ATT&amp;CK analogs are listed inside each technique as informational cross-references only — not exact mappings.</p>
  </div>
  <div class="matrix">{matrix_cols}</div>
</section>

<!-- DETECTIONS -->
<section id="detections" class="block">
  <div class="block-head">
    <p class="eyebrow">DEFENDER CONTENT</p>
    <h2>Detection Signatures</h2>
    <p class="sub">Shippable Suricata / Zeek / YARA content that detects the documented exposures. Tune SIDs and thresholds for your environment.</p>
  </div>
  <div class="grid det-grid">{det_cards}</div>
</section>

<!-- ABOUT -->
<section id="about" class="block about">
  <div class="block-head">
    <p class="eyebrow">MAINTAINER &amp; CITATION</p>
    <h2>About this reference</h2>
  </div>
  <div class="about-grid">
    <div>
      <p>Maintained by <b>{e(m['name'])}</b> — {e(m['role'])}.</p>
      <p class="links">
        <a href="{e(portfolio)}" target="_blank" rel="noopener">Portfolio ↗</a>
        <a href="{e(m['github'])}" target="_blank" rel="noopener">GitHub ↗</a>
        <a href="https://orcid.org/{e(orcid)}" target="_blank" rel="noopener">ORCID ↗</a>
      </p>
      <p class="note">{e(meta['data_note'])}</p>
      <p class="note pipeline"><b>Automation:</b> {e(meta['pipeline_note'])}</p>
    </div>
    <div class="cite">
      <p class="eyebrow">CITE</p>
      <pre><code>{e(meta['citation']['bibtex'])}</code></pre>
    </div>
  </div>
</section>
</main>

<footer class="foot">
  <span>{e(meta['title'])} v{e(meta['version'])} · built {e(meta['lastUpdated'])}</span>
  <span>Data: <a href="{e(meta['repo_url'])}" target="_blank" rel="noopener">/data on GitHub</a> · educational use, authorized testing only</span>
  <span class="nvd-attr">This product uses the NVD API but is not endorsed or certified by the NVD.</span>
</footer>

<script>{JS}</script>
</body>
</html>"""

(ROOT / "index.html").write_text(PAGE)
print(f"Built index.html  ·  {stats['cves']} CVEs, {stats['owasp']} OWASP, "
      f"{stats['techniques']} techniques, {stats['detections']} detections")
