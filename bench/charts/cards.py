"""The ladder's results as the two pictures security benchmarks are published with: a ranked board (a row an
entrant: a bar, then the figures beside it) and a strip of four cards (a claim, a line under it, a small chart).

    python3 -I cards.py ladder.json OUT_DIR

Reads the rows ladder.py reads (a value a list is a figure a run; the mean is drawn). Writes
OUT_DIR/board-{light,dark}.html and cards-{light,dark}.html: static pages, no script, system fonts, each sized to
be photographed by a headless browser at the width and height in its first line's comment."""
import json
import os
import sys
from html import escape

THEMES = {
    "light": {"bg": "#fcfcfb", "card": "#f3f2ee", "ink": "#1a1a19", "muted": "#6b6964", "line": "#e6e4df",
              "track": "#eceae5", "ours": "#2a78d6", "rest": "#b4b2ab", "plain": "#ffffff", "pill": "#dbe9fb"},
    "dark": {"bg": "#1a1a19", "card": "#242422", "ink": "#f2f1ee", "muted": "#a3a19a", "line": "#34332f",
             "track": "#2e2d2a", "ours": "#3987e5", "rest": "#6f6d67", "plain": "#3a3936", "pill": "#1d3554"},
}
FONT = "-apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif"
HERO = "DeepSeek V4 Flash"  # the entrant the cards speak for: the cheapest that catches everything


def mean(v):
    v = v if isinstance(v, list) else [v]
    return sum(v) / len(v)


def whole(v):
    """A count as it is printed: the runs' mean, or what they span when the mean is not a whole number."""
    v = v if isinstance(v, list) else [v]
    m = sum(v) / len(v)
    return f"{round(m)}" if m == round(m) or max(v) - min(v) > 1 else f"{min(v)}–{max(v)}"


def page(t, w, h, body, css):
    c = THEMES[t]
    vars_ = "".join(f"--{k}:{v};" for k, v in c.items())
    return (f"<!-- {w}x{h} -->\n<!doctype html><meta charset=utf-8><style>:root{{{vars_}}}"
            f"*{{box-sizing:border-box;margin:0}}body{{width:{w}px;height:{h}px;background:var(--bg);color:var(--ink);"
            f"font-family:{FONT};-webkit-font-smoothing:antialiased;padding:36px 40px}}"
            "h1{font-size:24px;font-weight:650;letter-spacing:-.01em}.sub{color:var(--muted);font-size:14px;margin-top:6px}"
            ".note{color:var(--muted);font-size:12px;line-height:1.55;margin-top:22px}"
            f"{css}</style><body>{body}</body>")


def board(spec, t):
    rows = []
    for r in spec["rows"]:
        rules = len(r["caught"]) == 1
        last = lambda k: r[k][0] if rules else r[k][1]
        rows.append({"name": r["model"], "tier": r["tier"], "rules": rules, "caught": last("caught"),
                     "ordinary": last("ordinary"), "cost": None if rules else last("cost"), "about": "cost" in r.get("about", [])})
    rows.sort(key=lambda r: (r["rules"], -mean(r["caught"]), mean(r["ordinary"])))
    out = ['<h1>Attacks caught in a year of a startup\'s logs</h1>',
           '<div class="sub">The same 59,342 records for every row: AWS, Okta, GitHub, Google Workspace and CI</div>',
           '<div class="head"><span>Watching the logs</span><span>Attacks caught, of 71</span><span></span>'
           '<span class="num">False alarms</span><span class="num">Fees a run</span></div>']
    for r in rows:
        kind = "detection rules, no model" if r["rules"] else (f"tangent, hosted models" if r["tier"] == "hosted" else f"tangent, open weights, {r['tier']}")
        cost = "none" if r["rules"] else ("~" if r["about"] else "") + f"${mean(r['cost']):,.2f}"
        out.append(f'<div class="row{" rules" if r["rules"] else ""}"><span><b>{escape(r["name"])}</b><i>{escape(kind)}</i></span>'
                   f'<span class="track"><span class="fill" style="width:{100 * mean(r["caught"]) / 71:.1f}%"></span></span>'
                   f'<span class="val">{whole(r["caught"])}</span><span class="num">{whole(r["ordinary"])}</span><span class="num">{cost}</span></div>')
    out.append('<div class="note">Open-weight rows: two runs each on 2026-11-16 through OpenRouter, their mean; what stood after the model reviewed its own '
               'alerts. Hosted: one earlier run. False alarms: ordinary records flagged, of 5,304 a model read. 36 of the 71 attacks are the cases the '
               'pipeline was developed on. Rules: Elastic\'s 350 public detection rules and Sigma\'s 102, over the same records.</div>')
    css = (".head,.row{display:grid;grid-template-columns:292px 1fr 58px 104px 96px;align-items:center;column-gap:14px}"
           ".head{margin-top:26px;padding-bottom:10px;border-bottom:1px solid var(--line);color:var(--muted);font-size:12.5px}"
           ".row{height:50px;font-size:14.5px}.row b{font-weight:600;display:block}.row i{font-style:normal;color:var(--muted);font-size:12px}"
           ".track{height:20px;background:var(--track);border-radius:4px;display:block}"
           ".fill{display:block;height:20px;background:var(--ours);border-radius:4px}.rules .fill{background:var(--rest)}"
           ".val{font-weight:650;font-variant-numeric:tabular-nums}.num{text-align:right;font-variant-numeric:tabular-nums}"
           ".rules b{font-weight:500}.row.rules:first-of-type{}")
    return page(t, 900, 150 + 50 * len(rows) + 104, "".join(out), css)


def bars(items, top, unit=""):
    """A card's chart: upright bars on one scale, the figure in each bar's head, ours filled."""
    cells = []
    for name, v, kind in items:
        cells.append(f'<div class="bar"><div class="col {kind}" style="height:{max(100 * v / top, 13):.1f}%"><em>{v:,}{unit}</em></div><span>{name}</span></div>')
    return f'<div class="bars">{"".join(cells)}</div>'


def cards(spec, t):
    by = {r["model"]: r for r in spec["rows"]}
    ours, elastic, sigma = by[HERO], by["Elastic detection rules"], by["Sigma rules"]
    caught, first, left = round(mean(ours["caught"][1])), round(mean(ours["ordinary"][0])), round(mean(ours["ordinary"][1]))
    cost, records = mean(ours["cost"][1]), 59342
    name = "tangent +<br>open model"
    c = [("Models catch what rules miss", "Attacks caught, of 71, in the same year of logs.",
          bars([(name, caught, "ours"), ("Elastic<br>rules", elastic["caught"][0], "plain"), ("Sigma<br>rules", sigma["caught"][0], "plain")], 71)),
         ("And raise fewer false alarms", "Ordinary records flagged, of 5,304.",
          bars([(name, left, "ours"), ("Elastic<br>rules", elastic["ordinary"][0], "plain"), ("Sigma<br>rules", sigma["ordinary"][0], "plain")], sigma["ordinary"][0])),
         ("A second look removes the noise", "The model reviews its own alerts with the whole log to query, and clears most of them.",
          f'<div class="delta"><b>−{round(100 * (first - left) / first)}%</b></div>' + bars([("first<br>pass", first, "plain"), ("after<br>review", left, "ours")], first)),
         ("On weights you can run yourself", f"{HERO}, open weights, fits a 256 GB machine at 4-bit. At hosted prices:",
          f'<div class="stat"><small>The year of logs</small><b>${cost:.2f}</b><span>a run</span></div>'
          f'<div class="stat"><small>Each 1,000 records</small><b>${1000 * cost / records:.2f}</b><span>in fees</span></div>')]
    out = ['<h1>An LLM watching the logs, against detection rules</h1>',
           '<div class="sub">A year of a startup\'s AWS, Okta, GitHub, Google Workspace and CI logs: 59,342 records, 71 attacks</div><div class="grid">']
    for title, text, chart in c:
        out.append(f'<div class="card"><h2>{title}</h2><p>{text}</p><div class="chart">{chart}</div></div>')
    out.append(f'</div><div class="note">tangent with {HERO} as judge and reviewer: two runs on 2026-11-16 through OpenRouter at 4-bit, their mean. '
               '36 of the 71 attacks are the cases the pipeline was developed on. Rules: Elastic\'s 350 public detection rules, run by Elasticsearch, and Sigma\'s 102.</div>')
    css = (".grid{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-top:26px}"
           ".card{background:var(--card);border-radius:18px;padding:22px 20px 18px;height:430px;display:flex;flex-direction:column}"
           ".card h2{font-size:18.5px;font-weight:620;line-height:1.2;letter-spacing:-.01em}.card p{color:var(--muted);font-size:13px;line-height:1.45;margin-top:10px}"
           ".chart{margin-top:auto;position:relative}.bars{display:flex;gap:8px;align-items:flex-end;height:190px}"
           ".bar{flex:1;height:100%;display:flex;flex-direction:column;justify-content:flex-end;align-items:center}"
           ".bar .col{width:100%;border-radius:8px 8px 4px 4px;background:var(--plain);display:flex;justify-content:center;min-height:30px}"
           ".bar .col.ours{background:var(--ours)}.bar em{font-style:normal;font-weight:650;font-size:15px;margin-top:6px;color:var(--ink)}"
           ".bar .col.ours em{color:#fff}.bar span{font-size:11.5px;color:var(--muted);text-align:center;line-height:1.25;margin-top:8px;height:44px;flex:none}"
           ".delta{position:absolute;right:0;top:-34px;left:50%;text-align:center}.delta b{background:var(--pill);border-radius:99px;padding:4px 10px;font-size:13px;font-weight:650}"
           ".stat{border-top:1px solid var(--line);padding:12px 0 8px}.stat small{display:block;color:var(--muted);font-size:12px}"
           ".stat b{font-size:40px;font-weight:680;letter-spacing:-.02em}.stat span{color:var(--muted);font-size:13px;margin-left:8px}")
    return page(t, 1120, 640, "".join(out), css)


spec, out = json.load(open(sys.argv[1])), sys.argv[2]
os.makedirs(out, exist_ok=True)
for t in THEMES:
    open(os.path.join(out, f"board-{t}.html"), "w").write(board(spec, t))
    open(os.path.join(out, f"cards-{t}.html"), "w").write(cards(spec, t))
