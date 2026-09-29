"""Generate the proxytui logo (banner + square icon).

    pip install matplotlib
    python assets/make_logo.py

Writes assets/logo.png, assets/logo.svg and assets/icon.png.
"""
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt                      # noqa: E402
import numpy as np                                   # noqa: E402
from matplotlib import font_manager                  # noqa: E402
from matplotlib.collections import LineCollection    # noqa: E402
from matplotlib.colors import LinearSegmentedColormap  # noqa: E402
from matplotlib.patches import FancyBboxPatch        # noqa: E402

OUT = Path(__file__).resolve().parent
BG_TOP, BG_BOTTOM = "#0a0f1e", "#131c38"
CYAN, VIOLET, WHITE, MUTED = "#22d3ee", "#a78bfa", "#f1f5f9", "#7c8aa5"
ROUTE = LinearSegmentedColormap.from_list("route", [CYAN, "#60a5fa", VIOLET])


def _font(*names):
    have = {f.name for f in font_manager.fontManager.ttflist}
    return next((n for n in names if n in have), "monospace")


MONO = _font("Cascadia Code", "Cascadia Mono", "JetBrains Mono", "Consolas", "DejaVu Sans Mono")
SANS = _font("Segoe UI", "Inter", "Helvetica", "DejaVu Sans")


def card(ax, x0, y0, w, h, r):
    """Rounded card filled with a vertical gradient."""
    patch = FancyBboxPatch((x0 + r, y0 + r), w - 2 * r, h - 2 * r,
                           boxstyle=f"round,pad={r}", lw=0, fc="none")
    ax.add_patch(patch)
    grad = np.linspace(0, 1, 256).reshape(-1, 1)
    cmap = LinearSegmentedColormap.from_list("bg", [BG_BOTTOM, BG_TOP])
    im = ax.imshow(grad, extent=(x0, x0 + w, y0, y0 + h), origin="lower",
                   cmap=cmap, aspect="auto", zorder=0)
    im.set_clip_path(patch)
    border = FancyBboxPatch((x0 + r, y0 + r), w - 2 * r, h - 2 * r,
                            boxstyle=f"round,pad={r}", lw=1.2,
                            ec=(1, 1, 1, 0.08), fc="none", zorder=1)
    ax.add_patch(border)


def glow_line(ax, x, y, width, zorder=3):
    pts = np.column_stack([x, y]).reshape(-1, 1, 2)
    segs = np.concatenate([pts[:-1], pts[1:]], axis=1)
    t = np.linspace(0, 1, len(segs))
    for mult, alpha in ((7, 0.05), (4.5, 0.08), (2.6, 0.16)):   # soft glow
        lc = LineCollection(segs, cmap=ROUTE, lw=width * mult, alpha=alpha,
                            capstyle="round", zorder=zorder)
        lc.set_array(t)
        ax.add_collection(lc)
    lc = LineCollection(segs, cmap=ROUTE, lw=width, capstyle="round", zorder=zorder + 1)
    lc.set_array(t)
    ax.add_collection(lc)


def glow_dot(ax, x, y, r, color, ring=False, zorder=6):
    for mult, alpha in ((3.2, 0.06), (2.2, 0.12), (1.5, 0.22)):
        ax.add_patch(plt.Circle((x, y), r * mult, color=color, alpha=alpha, lw=0, zorder=zorder))
    if ring:
        ax.add_patch(plt.Circle((x, y), r, fc=BG_TOP, ec=color, lw=0.3 * r * _ppu(ax),
                                zorder=zorder + 1))
        ax.add_patch(plt.Circle((x, y), r * 0.38, color=WHITE, zorder=zorder + 2))
    else:
        ax.add_patch(plt.Circle((x, y), r, color=color, zorder=zorder + 1))


def _ppu(ax) -> float:
    """Points per data unit, so line widths/fonts scale with the drawing."""
    x0, x1 = ax.get_xlim()
    return ax.figure.get_figwidth() * 72 / (x1 - x0)


def emblem(ax, cx, cy, s):
    """Route arc: you -> proxy (ring) -> internet, with a terminal prompt below."""
    ppu = _ppu(ax)
    t = np.linspace(0, 1, 300)
    a, p, b = np.array([cx - 0.62 * s, cy - 0.12 * s]), np.array([cx, cy + 0.95 * s]), \
        np.array([cx + 0.62 * s, cy - 0.12 * s])
    curve = ((1 - t) ** 2)[:, None] * a + (2 * (1 - t) * t)[:, None] * p + (t ** 2)[:, None] * b
    glow_line(ax, curve[:, 0], curve[:, 1], width=0.024 * s * ppu)
    top = curve[len(curve) // 2]
    glow_dot(ax, *a, 0.075 * s, CYAN)
    glow_dot(ax, *b, 0.075 * s, VIOLET)
    glow_dot(ax, *top, 0.12 * s, "#60a5fa", ring=True)
    ax.text(cx, cy - 0.5 * s, "›_", color=WHITE, fontsize=0.24 * s * ppu, family=MONO,
            weight="bold", ha="center", va="center", zorder=8)


def banner():
    fig = plt.figure(figsize=(8, 2.4), dpi=200)
    fig.patch.set_alpha(0)
    ax = fig.add_axes((0, 0, 1, 1))
    ax.set_xlim(0, 8), ax.set_ylim(0, 2.4), ax.axis("off")
    card(ax, 0.04, 0.04, 7.92, 2.32, 0.28)
    emblem(ax, 1.25, 1.12, 1.0)

    word = ax.text(2.45, 1.38, "proxy", color=WHITE, fontsize=50, family=MONO,
                   weight="bold", va="center", zorder=8)
    fig.canvas.draw()
    bb = word.get_window_extent().transformed(ax.transData.inverted())
    ax.text(bb.x1, 1.38, "tui", color=CYAN, fontsize=50, family=MONO,
            weight="bold", va="center", zorder=8)
    ax.text(2.49, 0.72, "pick a proxy  ·  verify it  ·  route through it",
            color=MUTED, fontsize=13, family=SANS, va="center", zorder=8)
    for i, c in enumerate((CYAN, "#60a5fa", VIOLET)):              # accent bar
        ax.add_patch(FancyBboxPatch((2.5 + i * 0.32, 0.36), 0.24, 0.035,
                                    boxstyle="round,pad=0.01", fc=c, lw=0, zorder=8))
    for ext in ("png", "svg"):
        fig.savefig(OUT / f"logo.{ext}", transparent=True)
    plt.close(fig)


def icon():
    fig = plt.figure(figsize=(2.56, 2.56), dpi=200)
    fig.patch.set_alpha(0)
    ax = fig.add_axes((0, 0, 1, 1))
    ax.set_xlim(0, 1), ax.set_ylim(0, 1), ax.axis("off")
    card(ax, 0.02, 0.02, 0.96, 0.96, 0.18)
    emblem(ax, 0.5, 0.47, 0.42)
    fig.savefig(OUT / "icon.png", transparent=True)
    plt.close(fig)


if __name__ == "__main__":
    banner()
    icon()
    print(f"wrote {OUT / 'logo.png'}, {OUT / 'logo.svg'}, {OUT / 'icon.png'}")
