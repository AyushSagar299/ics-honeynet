# shared plot settings for the report figures, so all of them look the same.
# the paths are worked out from where this file sits, so it runs on any machine.
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import os

FIGS = os.path.dirname(os.path.abspath(__file__))              # analysis/report_figures
REPO = os.path.dirname(os.path.dirname(FIGS))                  # the project folder
C = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#6250d6"]
GREY = "#52514e"
ATTACK = "#e34948"

plt.rcParams.update({
    "figure.facecolor": "white", "axes.facecolor": "white", "savefig.facecolor": "white",
    "font.size": 11, "axes.labelsize": 11, "axes.titlesize": 12, "legend.fontsize": 10,
    "xtick.labelsize": 10, "ytick.labelsize": 10,
    "axes.spines.top": False, "axes.spines.right": False,
    "axes.grid": True, "grid.color": "#e4e3df", "grid.linewidth": 0.6,
    "axes.axisbelow": True, "lines.linewidth": 1.4,
})


def save(fig, name):
    p = os.path.join(FIGS, name)
    fig.savefig(p, dpi=200, bbox_inches="tight")
    print("wrote", p)
