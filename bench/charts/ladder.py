"""The ladder as pictures: a chart a measure (efficacy, noise, cost), a row a memory tier, hosted, or a SIEM's rules.

    python3 -I ladder.py DATA.json OUT_DIR

DATA.json: {"legend": [single, double, rules],
            "charts": [{"name", "key", "title", "subtitle", "scale": "linear"|"log", "domain": [a, b], "ticks": [...],
                        "format": "int"|"usd", "figure": "mean" (the runs' mean beside the plot, not their span),
                        "note": [...]}],
            "rows": [{"tier", "model", "<key>": [single, double] | [rules], "about": [keys whose figures are estimates],
                      "apart": bool}]}
A row with two values is a dumbbell: the single pass in the light shade, the double pass in the dark one, on top,
so a row the reviewer did not move shows one dot with a halo. A row with one value is a SIEM's rules, in gray.
A value may be a list, a figure a run: the dot is their mean, a bar under it spans the lowest to the highest,
and the figure beside the plot is that span.
ladder-<name>-light.svg and ladder-<name>-dark.svg: static, no script, system fonts, as chart.py's."""
import json
import math
import os
import sys
from html import escape

THEMES = {
    "light": {"bg": "#fcfcfb", "ink": "#1a1a19", "muted": "#6b6964", "grid": "#e6e4df", "one": "#86b6ef", "two": "#2a78d6", "rest": "#b4b2ab"},
    "dark": {"bg": "#1a1a19", "ink": "#f2f1ee", "muted": "#a3a19a", "grid": "#34332f", "one": "#184f95", "two": "#3987e5", "rest": "#6f6d67"},
}
W, PAD, ROW = 760, 32, 32
TIER, LABEL, TRACK = 70, 256, 318   # the tier's column, the whole label column, the plot; the figures take the rest
FONT = "-apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif"


def place(ch, v):
    a, b = ch["domain"]
    if ch["scale"] == "log":
        return TRACK * (math.log10(v) - math.log10(a)) / (math.log10(b) - math.log10(a))
    return TRACK * (v - a) / (b - a)


def figure(ch, v, about=False):
    s = f"${v:,.2f}" if ch["format"] == "usd" and v else ("$0" if ch["format"] == "usd" else f"{v:,}")
    return ("~" if about else "") + s


def runs(v):
    """A value as its runs: (mean, lowest, highest)."""
    v = v if isinstance(v, list) else [v]
    return sum(v) / len(v), min(v), max(v)


def span(ch, v, about=False):
    """The figure beside the plot: the value, or lowest–highest when its runs differ."""
    mean, lo, hi = runs(v)
    if ch.get("figure") == "mean":  # runs that differ by cents: their mean says it
        return figure(ch, round(mean, 2), about)
    return figure(ch, lo, about) if lo == hi else f"{figure(ch, lo, about)}–{figure(ch, hi).lstrip('$')}"


def draw(spec, ch, t):
    c = THEMES[t]
    out, y = [], PAD + 22
    text = lambda x, yy, s, size=13, fill=c["ink"], weight=400, anchor="start": (
        f'<text x="{x:.1f}" y="{yy:.1f}" font-size="{size}" font-weight="{weight}" text-anchor="{anchor}" fill="{fill}">{s}</text>')
    out.append(text(PAD, y, escape(ch["title"]), 20, weight=600))
    y += 22
    out.append(text(PAD, y, escape(ch["subtitle"]), 13, c["muted"]))
    y += 28
    x = PAD
    for shade, r, name in zip((c["one"], c["two"], c["rest"]), (6.5, 4.5, 5.5), spec["legend"]):
        out.append(f'<circle cx="{x + 7}" cy="{y - 4.5}" r="{r}" fill="{shade}"/>')
        out.append(text(x + 20, y, escape(name), 13))
        x += 20 + 6.6 * len(name) + 22
    y += 20
    top, px = y, PAD + LABEL
    rows_h = ROW * len(spec["rows"]) + sum(14 for r in spec["rows"] if r.get("apart"))
    for tick in ch["ticks"]:
        tx = px + place(ch, tick)
        out.append(f'<line x1="{tx:.1f}" y1="{top}" x2="{tx:.1f}" y2="{top + rows_h}" stroke="{c["grid"]}" stroke-width="1"/>')
        out.append(text(tx, top + rows_h + 16, figure(ch, tick).replace(".00", ""), 11.5, c["muted"], anchor="middle"))
    for r in spec["rows"]:
        if r.get("apart"):  # hosted, and the rules, set off from the tiers
            out.append(f'<line x1="{PAD}" y1="{y + 7}" x2="{W - PAD}" y2="{y + 7}" stroke="{c["grid"]}" stroke-width="1"/>')
            y += 14
        mid, vals = y + ROW / 2, r[ch["key"]]
        about = ch["key"] in r.get("about", [])
        out.append(text(PAD, mid + 4.5, escape(r["tier"]), 13, weight=600))
        out.append(text(PAD + TIER, mid + 4.5, escape(r["model"]), 13))
        fx = px + TRACK + 16
        if len(vals) == 1:
            a = px + place(ch, max(vals[0], ch["domain"][0]))
            out.append(f'<g><title>{escape(r["model"])}: {figure(ch, vals[0])}</title>'
                       f'<circle cx="{a:.1f}" cy="{mid}" r="5.5" fill="{c["rest"]}" stroke="{c["bg"]}" stroke-width="2"/></g>')
            out.append(text(fx, mid + 4.5, figure(ch, vals[0]), 13, weight=600))
        else:
            one, two = vals
            (m1, lo1, hi1), (m2, lo2, hi2) = runs(one), runs(two)
            floor = lambda v: max(v, ch["domain"][0])
            a, b = px + place(ch, floor(m1)), px + place(ch, floor(m2))
            tip = f'{r["tier"]}, {r["model"]}: {span(ch, one, about)} judge alone, {span(ch, two, about)} with the reviewer'
            out.append(f'<g><title>{escape(tip)}</title>')
            if abs(a - b) > 0.5:
                out.append(f'<line x1="{a:.1f}" y1="{mid}" x2="{b:.1f}" y2="{mid}" stroke="{c["rest"]}" stroke-width="2" stroke-linecap="round"/>')
            for lo, hi, shade in ((lo1, hi1, c["one"]), (lo2, hi2, c["two"])):  # what the runs span
                x1, x2 = px + place(ch, floor(lo)), px + place(ch, floor(hi))
                if x2 - x1 > 1:
                    out.append(f'<line x1="{x1:.1f}" y1="{mid}" x2="{x2:.1f}" y2="{mid}" stroke="{shade}" stroke-width="5" stroke-linecap="round" opacity="0.55"/>')
            out.append(f'<circle cx="{a:.1f}" cy="{mid}" r="6.5" fill="{c["one"]}" stroke="{c["bg"]}" stroke-width="2"/>')
            out.append(f'<circle cx="{b:.1f}" cy="{mid}" r="4.5" fill="{c["two"]}" stroke="{c["bg"]}" stroke-width="1.5"/>')
            out.append('</g>')
            # the figures beside the plot: the single pass, then where the reviewer left it
            if one == two:
                out.append(text(fx, mid + 4.5, span(ch, two, about), 13, weight=600))
            else:
                out.append(f'<text x="{fx}" y="{mid + 4.5}" font-size="13" fill="{c["muted"]}">{span(ch, one, about)} → '
                           f'<tspan font-weight="600" fill="{c["ink"]}">{span(ch, two, about)}</tspan></text>')
        y += ROW
    y += 26
    for line in ch.get("note", []):
        y += 18
        out.append(text(PAD, y, escape(line), 11.5, c["muted"]))
    h = y + PAD
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {h}" width="{W}" height="{h}" font-family="{FONT}" role="img" '
            f'aria-label="{escape(ch["title"])}">\n<rect width="{W}" height="{h}" rx="10" fill="{c["bg"]}"/>\n' + "\n".join(out) + "\n</svg>\n")


spec, out = json.load(open(sys.argv[1])), sys.argv[2]
os.makedirs(out, exist_ok=True)
for ch in spec["charts"]:
    for t in THEMES:
        open(os.path.join(out, f"ladder-{ch['name']}-{t}.svg"), "w").write(draw(spec, ch, t))
