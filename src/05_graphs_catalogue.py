"""Graphiques du catalogue. Ce soir : la charge comparée. Les trois autres sont prêts, décommente au besoin."""
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from common import OUT, stamps

cat = pd.read_parquet(OUT / "catalogue.parquet")
charge = pd.read_csv(OUT / "charge_comparee.csv")
st = stamps()
foot = (f"Sources : NVD {st.get('nvd',{}).get('fetched','')}, CISA KEV {st.get('kev',{}).get('fetched','')}, "
        f"FIRST EPSS {str(st.get('epss',{}).get('score_date',''))[:10]}")

plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 10, "axes.spines.top": False, "axes.spines.right": False})

# ---- 1. charge comparée
fig, ax = plt.subplots(figsize=(9, 5))
labels = ["CVSS ≥ 9", "CVSS ≥ 7", "KEV seul", "KEV ou EPSS ≥ 0,10\nou (CVSS ≥ 9 et réseau)"]
bars = ax.barh(labels, charge.cve_a_traiter, color=["#b8b8b8", "#8c8c8c", "#1f3864", "#2e75b6"])
for b, n, k in zip(bars, charge.cve_a_traiter, charge.kev_couvertes_pct):
    ax.text(b.get_width() + charge.cve_a_traiter.max() * 0.01, b.get_y() + b.get_height() / 2,
            f"{n:,} CVE à traiter · {k:.0f} % des KEV couvertes".replace(",", " "), va="center")
ax.set_xlim(0, charge.cve_a_traiter.max() * 1.45)
ax.invert_yaxis()
ax.set_xlabel("Nombre de CVE à traiter")
ax.set_title("Quatre stratégies de priorisation : charge de travail et couverture des CVE exploitées")
fig.text(0.01, 0.01, foot, fontsize=8, color="#666")
fig.tight_layout(rect=(0, 0.03, 1, 1))
fig.savefig(OUT / "charge_comparee.png", dpi=150)
print("charge_comparee.png")

# ---- 2. répartition RBVM vs CVSS (barres empilées)
fig, ax = plt.subplots(figsize=(7, 5))
rb = cat.niveau.value_counts().reindex(["P1", "P2", "P3", "P4"]).fillna(0)
cv = cat.classe_cvss.value_counts().reindex(["Critique", "Élevé", "Moyen", "Faible", "Non noté"]).fillna(0)
cols_rb = ["#c00000", "#ed7d31", "#ffc000", "#d9d9d9"]; cols_cv = ["#c00000", "#ed7d31", "#ffc000", "#d9d9d9", "#f2f2f2"]
for x, series, cols in ((0, rb, cols_rb), (1, cv, cols_cv)):
    bottom = 0
    for (lab, val), c in zip(series.items(), cols):
        ax.bar(x, val, bottom=bottom, color=c, width=0.6, edgecolor="white")
        if val > len(cat) * 0.03:
            ax.text(x, bottom + val / 2, f"{lab}\n{int(val):,}".replace(",", " "), ha="center", va="center", fontsize=9)
        bottom += val
ax.set_xticks([0, 1]); ax.set_xticklabels(["Grille RBVM (KEV → EPSS → CVSS)", "Sévérité CVSS seule"])
ax.set_ylabel("Nombre de CVE"); ax.set_title("Même catalogue, deux façons de dire « urgent »")
fig.text(0.01, 0.01, foot, fontsize=8, color="#666"); fig.tight_layout(rect=(0, 0.03, 1, 1))
fig.savefig(OUT / "repartition_rbvm_vs_cvss.png", dpi=150); print("repartition_rbvm_vs_cvss.png")

# ---- 3. nuage CVSS × EPSS, KEV en couleur
s = cat.dropna(subset=["cvss", "epss"])
fig, ax = plt.subplots(figsize=(8, 5.5))
ax.scatter(s[~s.dans_kev].cvss, s[~s.dans_kev].epss, s=3, alpha=0.15, color="#9dc3e6", label="hors KEV")
ax.scatter(s[s.dans_kev].cvss, s[s.dans_kev].epss, s=8, alpha=0.7, color="#c00000", label="dans KEV")
ax.set_yscale("log"); ax.set_ylim(1e-5, 1.2); ax.set_xlabel("CVSS"); ax.set_ylabel("EPSS (échelle log)")
ax.axhline(0.10, ls="--", color="#444", lw=0.8); ax.text(0.2, 0.12, "seuil EPSS 0,10", fontsize=8)
ax.axvline(7.0, ls="--", color="#444", lw=0.8); ax.text(7.05, 2e-5, "CVSS 7", fontsize=8)
ax.legend(loc="lower left"); ax.set_title("La sévérité ne prédit pas l'exploitation")
fig.text(0.01, 0.01, foot, fontsize=8, color="#666"); fig.tight_layout(rect=(0, 0.03, 1, 1))
fig.savefig(OUT / "cvss_vs_epss.png", dpi=150); print("cvss_vs_epss.png")

# ---- 4. top 20 produits par CVE P1
prod = pd.read_csv(OUT / "produits.csv").head(20)
fig, ax = plt.subplots(figsize=(9, 6.5))
lab = (prod.editeur + " / " + prod.produit).str.replace("_", " ")
ax.barh(lab, prod.cve_p1, color="#c00000", label="P1 (KEV)")
ax.barh(lab, prod.cve_p2, left=prod.cve_p1, color="#ed7d31", label="P2")
ax.invert_yaxis(); ax.set_xlabel("Nombre de CVE"); ax.legend()
ax.set_title("Vingt produits concentrent l'essentiel des CVE exploitées")
fig.text(0.01, 0.01, foot, fontsize=8, color="#666"); fig.tight_layout(rect=(0, 0.03, 1, 1))
fig.savefig(OUT / "top20_produits.png", dpi=150); print("top20_produits.png")
