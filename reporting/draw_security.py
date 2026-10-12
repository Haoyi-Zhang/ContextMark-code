"""Draw the two retained synthetic-security groupplots as vector PDFs.

This is a presentation conversion, not a security experiment. Read the canonical
artifact/results/derived CSVs without recalculating, fitting, or extrapolating
either curve. Paths are anchored to this script, not the working directory.

Run with Python, matplotlib 3.10.8, numpy 2.3.5 and fontTools. Use only existing
TrueType fonts, in order: TeX Gyre Termes, Times New Roman, Liberation Serif.
The installed font manager supplies the Windows Times / Linux Liberation
fallback; --font-dir can select an existing directory containing these TTFs.
No font is installed, converted or redistributed as a standalone font file.
The two stable PDF outputs are placed next to this editable source, or in --outdir. No raster
image is included in the PDF and no TeX compiler is invoked by this script.
"""

from __future__ import annotations

import argparse
import csv
import io
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
from matplotlib import font_manager, pyplot as plt, ticker
from fontTools.ttLib import TTFont
import numpy as np


HERE = Path(__file__).resolve().parent
DATA = HERE.parent / "results" / "derived"
OUTPUT = HERE
GAMES = ("removal", "nontransfer", "unforgeability", "collusion")
MAIN_TITLES = (
    "(a) removal", "(b) non-transferability",
    "(c) origin unforgeability", "(d) coalition survival",
)
SUPPLEMENT_TITLES = ("removal", "non-transferability", "origin", "coalition")
MAIN_TICKS = (1, 4, 16, 64, 256)
# The original supplement declared these ticks. The last two are outside the
# unchanged automatic data limits and therefore do not appear (as in PGFPlots).
SUPPLEMENT_TICKS = (*MAIN_TICKS, 1024, 2048)


def register_fonts(font_dir: Path | None) -> str:
    if font_dir is not None:
        font_dir = font_dir.resolve(strict=True)
        for path in sorted(font_dir.glob("*.ttf")):
            font_manager.fontManager.addfont(str(path))
    entries = [entry for entry in font_manager.fontManager.ttflist
               if Path(entry.fname).suffix.lower() == ".ttf"
               and (font_dir is None or Path(entry.fname).resolve().parent == font_dir)]
    roles = (("normal", 400), ("normal", 700), ("italic", 400), ("italic", 700))
    required = set(" ".join((*MAIN_TITLES, *SUPPLEMENT_TITLES)))
    required.update("0123456789compiled probabilitysuccessful contexts Q\u2212")
    for family in ("TeX Gyre Termes", "Times New Roman", "Liberation Serif"):
        chosen = []
        for style, weight in roles:
            candidates = [entry for entry in entries if entry.name == family
                          and entry.style == style
                          and font_manager.weight_dict.get(entry.weight, entry.weight) == weight]
            valid = []
            for entry in sorted(candidates, key=lambda item: item.fname):
                path = Path(entry.fname).resolve(strict=True)
                with TTFont(path) as font:
                    # Reject CFF, restricted embedding, no-subsetting and
                    # bitmap-only embedding. No outline conversion is attempted.
                    if "glyf" not in font or "CFF " in font or "CFF2" in font:
                        continue
                    if font["OS/2"].fsType & (0x0002 | 0x0100 | 0x0200):
                        continue
                    if not required.issubset(chr(code) for code in font.getBestCmap()):
                        continue
                    valid.append((path, font["name"].getDebugName(6),
                                  font["name"].getDebugName(5), font["OS/2"].fsType))
            if not valid:
                break
            chosen.append((style, weight, *valid[0]))
        if len(chosen) != len(roles):
            print(f"font family unavailable as complete embeddable TrueType set: {family}")
            continue
        # A process-local lookup alias pins the exact selected TTFs for both
        # text and math, even if an OTF of the same family is also installed.
        # The embedded PDF names are the real font PostScript names, not this alias.
        alias = "P029 Plot Serif"
        for style, weight, path, ps_name, version, fs_type in chosen:
            font_manager.fontManager.addfont(str(path))
            font_manager.fontManager.ttflist.append(font_manager.FontEntry(
                fname=str(path), name=alias, style=style, weight=weight,
            ))
            print(f"font: {family}, {style}/{weight}, {ps_name}, {version}, fsType={fs_type}: {path}")
        for style, weight, path, *_ in chosen:
            properties = font_manager.FontProperties(family=alias, style=style, weight=weight)
            resolved = Path(font_manager.findfont(properties, fallback_to_default=False)).resolve()
            if resolved != path:
                raise ValueError(f"Unexpected font fallback: {resolved}, expected {path}")
        return alias
    raise RuntimeError("No complete, embeddable Times-compatible TrueType family is installed")


def load_data() -> tuple[dict[str, np.ndarray], dict[Path, bytes]]:
    curves = {}
    originals = {}
    for game in GAMES:
        path = DATA / f"security-{game}.csv"
        original = path.read_bytes()
        rows = list(csv.DictReader(io.StringIO(original.decode("utf-8-sig"))))
        values = np.asarray([
            [float(row["queries"]), float(row["theorem_bound"]), float(row["independent_model"])]
            for row in rows
        ])
        if values.shape != (9, 3) or not np.array_equal(values[:, 0], 2.0 ** np.arange(9)):
            raise ValueError(f"Unexpected retained query domain: {path}")
        if not np.all(np.isfinite(values)) or not np.all(values > 0):
            raise ValueError(f"Invalid log-axis data: {path}")
        if any(row["game"] != game or int(row["records"]) != 4 * int(row["queries"]) for row in rows):
            raise ValueError(f"Unexpected source rows: {path}")
        curves[game] = values
        originals[path] = original
    return curves, originals


def original_log_limits(values: np.ndarray) -> tuple[float, float]:
    """PGFPlots' default 10% enlargement in transformed log coordinates."""
    low, high = float(np.min(values)), float(np.max(values))
    factor = (high / low) ** 0.1
    return low / factor, high * factor


def draw(curves: dict[str, np.ndarray], supplement: bool) -> Path:
    # PDF points (1/72 inch). The axis boxes and panel separations are retained
    # from the original rendered PGFPlots figures. Small outer-padding changes
    # accommodate 9-point Times-compatible text, without scaling at TeX inclusion time.
    if supplement:
        width, height = 440.0, 269.004
        xs, ys = (41.0, 259.736), (168.380, 28.0)
        axis_width, axis_height = 176.219, 83.687
        titles, ticks = SUPPLEMENT_TITLES, SUPPLEMENT_TICKS
        filename = "security-bounds-supplement.pdf"
    else:
        width, height = 445.0, 217.825
        xs, ys = (41.0, 258.385), (128.820, 27.0)
        axis_width, axis_height = 183.938, 67.238
        titles, ticks = MAIN_TITLES, MAIN_TICKS
        filename = "security-bounds.pdf"

    fig = plt.figure(figsize=(width / 72, height / 72))
    fig.set_facecolor("white")
    for index, game in enumerate(GAMES):
        row, column = divmod(index, 2)
        values = curves[game]
        ax = fig.add_axes([
            xs[column] / width, ys[row] / height,
            axis_width / width, axis_height / height,
        ])
        ax.set_xscale("log", base=2)
        ax.set_yscale("log", base=10)
        ax.set_xlim(original_log_limits(values[:, 0]))
        ax.set_ylim(original_log_limits(values[:, 1:]))
        ax.xaxis.set_major_locator(ticker.FixedLocator(ticks))
        ax.xaxis.set_major_formatter(ticker.FuncFormatter(lambda value, _: f"{value:g}"))
        ax.xaxis.set_minor_locator(ticker.NullLocator())
        ax.yaxis.set_major_locator(ticker.LogLocator(base=10, subs=(1.0,)))
        ax.yaxis.set_major_formatter(ticker.LogFormatterMathtext(base=10))
        ax.yaxis.set_minor_locator(ticker.LogLocator(base=10, subs=np.arange(2, 10)))
        ax.yaxis.set_minor_formatter(ticker.NullFormatter())
        ax.set_axisbelow(True)
        ax.grid(which="major", color="0.87" if supplement else "0.88", linewidth=0.38)
        for spine in ax.spines.values():
            spine.set_color("0.30")
            spine.set_linewidth(0.40 if supplement else 0.52)
        ax.tick_params(which="major", direction="in", top=True, right=True,
                       length=3, width=0.38, color="0.70", pad=2.7, labelsize=9)
        ax.tick_params(which="minor", direction="in", right=True,
                       length=1.7, width=0.20, color="0.75")
        line_width = 0.40 if supplement else 1.08
        marker_size = 4.0
        solid, = ax.plot(values[:, 0], values[:, 1], color="black", linestyle="-",
                         linewidth=line_width, marker="o", markersize=marker_size,
                         markeredgewidth=line_width, markerfacecolor="black")
        dashed, = ax.plot(values[:, 0], values[:, 2], color="0.45", linestyle=(0, (4, 2)),
                          linewidth=line_width, marker="^", markersize=marker_size,
                          markeredgewidth=line_width, markerfacecolor="none")
        for line, source_column in ((solid, 1), (dashed, 2)):
            if not np.array_equal(line.get_xdata(), values[:, 0]):
                raise AssertionError("Plotted query coordinates changed")
            if not np.array_equal(line.get_ydata(), values[:, source_column]):
                raise AssertionError("Plotted probability coordinates changed")
        ax.set_title(titles[index], fontsize=9, fontweight="bold", pad=8)
        if column == 0:
            ax.set_ylabel("probability" if supplement else "compiled probability",
                          fontsize=9, labelpad=8)
        if supplement or row == 1:
            ax.set_xlabel("contexts" if supplement else r"successful contexts $Q$",
                          fontsize=9, labelpad=4)
        else:
            ax.tick_params(labelbottom=False)
        print(f"{filename}: {game}, 9 points/curve, xlim={ax.get_xlim()}, ylim={ax.get_ylim()}")

    # Original groupplots have no in-plot legend: the unmodified TeX captions
    # identify solid bounds versus dashed independent-event arithmetic checks.
    target = OUTPUT / filename
    fig.savefig(target, format="pdf", metadata={
        "Creator": "draw_security.py / matplotlib",
        "Title": "Illustrative synthetic security calculations",
        "CreationDate": None,
        "ModDate": None,
    })
    plt.close(fig)
    return target


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--font-dir", type=Path, help="Existing directory of Times-compatible TrueType fonts")
    parser.add_argument("--outdir", type=Path, default=HERE, help="Directory for the two vector PDFs")
    args = parser.parse_args()
    global OUTPUT
    OUTPUT = args.outdir.resolve()
    OUTPUT.mkdir(parents=True, exist_ok=True)
    family = register_fonts(args.font_dir)
    curves, originals = load_data()
    with matplotlib.rc_context({
        "font.family": family, "font.size": 9,
        "axes.titlesize": 9, "axes.labelsize": 9,
        "xtick.labelsize": 9, "ytick.labelsize": 9,
        "mathtext.fontset": "custom",
        "mathtext.rm": family, "mathtext.it": f"{family}:italic",
        "mathtext.bf": f"{family}:bold", "mathtext.bfit": f"{family}:bold:italic",
        "mathtext.sf": family, "mathtext.tt": family, "mathtext.cal": family,
        "mathtext.fallback": None, "text.usetex": False,
        "pdf.fonttype": 42, "pdf.use14corefonts": False,
        "path.simplify": False,
    }):
        for supplement in (False, True):
            print(f"wrote: {draw(curves, supplement)}")
    for path, original in originals.items():
        if path.read_bytes() != original:
            raise AssertionError(f"Input CSV changed: {path}")
    print("CSV byte comparison: all four canonical inputs unchanged")


if __name__ == "__main__":
    main()
