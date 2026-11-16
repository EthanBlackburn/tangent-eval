"""The comparison as pictures for a README: tangent, Elastic's detection rules and Sigma's on the same logs.

    python3 -I chart.py DATA.json OUT_DIR

DATA.json: {"<name>": {"title": ..., "subtitle": ..., "note": ..., "panels": [{"title": ..., "of": N, "lower": bool,
            "rows": [["tangent", n], ["Elastic rules", n], ["Sigma rules", n]]}]}}
One SVG a name and theme (<name>-light.svg, <name>-dark.svg): static, no script, system fonts."""
import json
import os
import sys
from html import escape

THEMES = {
    "light": {"bg": "#fcfcfb", "ink": "#1a1a19", "muted": "#6b6964", "grid": "#e6e4df", "hero": "#2a78d6", "rest": "#b4b2ab"},
    "dark": {"bg": "#1a1a19", "ink": "#f2f1ee", "muted": "#a3a19a", "grid": "#34332f", "hero": "#3987e5", "rest": "#6f6d67"},
}
W, PAD, LABEL, BAR, GAP = 760, 32, 118, 20, 10
FONT = "-apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif"


def bar(x, y, w, h, fill):
    """A bar from the baseline at x, its far end rounded."""
    r = min(4, w / 2)
    if w <= 0:
        return ""
    return f'<path d="M{x},{y}h{w - r:.1f}a{r},{r} 0 0 1 {r},{r}v{h - 2 * r}a{r},{r} 0 0 1 -{r},{r}h-{w - r:.1f}z" fill="{fill}"/>'


def draw(spec, t):
    c = THEMES[t]
    out, y = [], PAD + 22
    out.append(f'<text x="{PAD}" y="{y}" font-size="20" font-weight="600" fill="{c["ink"]}">{escape(spec["title"])}</text>')
    if spec.get("subtitle"):
        y += 22
        out.append(f'<text x="{PAD}" y="{y}" font-size="13" fill="{c["muted"]}">{escape(spec["subtitle"])}</text>')
    y += 14
    track = W - 2 * PAD - LABEL - 96
    for p in spec["panels"]:
        y += 30
        hint = "lower is better" if p.get("lower") else "higher is better"
        out.append(f'<text x="{PAD}" y="{y}" font-size="14" font-weight="600" fill="{c["ink"]}">{escape(p["title"])}'
                   f'<tspan font-weight="400" fill="{c["muted"]}">  ·  {hint}</tspan></text>')
        y += 12
        top = max(n for _, n in p["rows"])
        scale = p["of"] if not p.get("lower") else max(top * 1.15, 1)
        for name, n in p["rows"]:
            hero = name == "tangent"
            x0 = PAD + LABEL
            out.append(f'<text x="{x0 - 12}" y="{y + BAR / 2 + 4.5}" font-size="13" text-anchor="end" '
                       f'font-weight="{600 if hero else 400}" fill="{c["ink"]}">{escape(name)}</text>')
            out.append(f'<rect x="{x0}" y="{y}" width="{track}" height="{BAR}" rx="4" fill="{c["grid"]}" opacity="0.55"/>')
            w = track * n / scale
            out.append(bar(x0, y, max(w, 2 if n else 0), BAR, c["hero"] if hero else c["rest"]))
            label = f'{n:,}' + (f'<tspan fill="{c["muted"]}" font-weight="400"> of {p["of"]:,}</tspan>' if p.get("of") else "")
            out.append(f'<text x="{x0 + track + 10}" y="{y + BAR / 2 + 4.5}" font-size="13" font-weight="600" fill="{c["ink"]}">{label}</text>')
            y += BAR + GAP
        y += 2
    if spec.get("note"):
        for line in spec["note"]:
            y += 18
            out.append(f'<text x="{PAD}" y="{y}" font-size="11.5" fill="{c["muted"]}">{escape(line)}</text>')
    h = y + PAD
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {h}" width="{W}" height="{h}" font-family="{FONT}" role="img" '
            f'aria-label="{escape(spec["title"])}">\n<rect width="{W}" height="{h}" rx="10" fill="{c["bg"]}"/>\n' + "\n".join(o for o in out if o) + "\n</svg>\n")


data, out = json.load(open(sys.argv[1])), sys.argv[2]
os.makedirs(out, exist_ok=True)
for name, spec in data.items():
    for t in THEMES:
        open(os.path.join(out, f"{name}-{t}.svg"), "w").write(draw(spec, t))
