"""Deux graphiques pour le COPIL : l'entonnoir et le top 15 des paquets."""
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from common import DATA, OUT, stamps

det = pd.read_parquet(DATA / "detections.parquet"); det = det[det.est_cve]
cve = pd.read_parquet(OUT / "cve_uniques.parquet")
paq = pd.read_csv(OUT / "paquets.csv")
st = stamps()
foot = (f"Sources : Trivy {st.get('trivy',{}).get('fetched','')} ({st.get('trivy',{}).get('postes','')} postes), "
        f"CISA KEV {st.get('kev',{}).get('fetched','')}, FIRST EPSS {str(st.get('epss',{}).get('score_date',''))[:10]}")
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 10, "axes.spines.top": False, "axes.spines.right": False})
fmt = lambda n: f"{n:,}".replace(",", " ")

# ---- entonnoir
steps = [("Détections brutes", len(det)), ("CVE uniques", len(cve)), ("Paquets concernés", paq.paquet.nunique()),
         ("Paquets avec CVE urgentes (P1/P2)", int((paq.cve_urgentes > 0).sum())),
         ("Paquets des campagnes du mois", min(10, int((paq.correctif_dispo == "oui").sum())))]
fig, ax = plt.subplots(figsize=(9, 4.8))
labels = [s[0] for s in steps]; vals = [s[1] for s in steps]
bars = ax.barh(labels, vals, color=["#9dc3e6", "#2e75b6", "#1f3864", "#ed7d31", "#c00000"])
for b, v in zip(bars, vals):
    ax.text(b.get_width() + max(vals) * 0.01, b.get_y() + b.get_height() / 2, fmt(v), va="center")
ax.invert_yaxis(); ax.set_xlim(0, max(vals) * 1.15); ax.set_xlabel("Nombre")
ax.set_title("Du volume brut aux décisions : l'entonnoir")
fig.text(0.01, 0.01, foot, fontsize=8, color="#666"); fig.tight_layout(rect=(0, 0.03, 1, 1))
fig.savefig(OUT / "entonnoir.png", dpi=150); print("entonnoir.png")

# ---- top 15 paquets
top = paq.head(15)
fig, ax = plt.subplots(figsize=(9, 6))
ax.barh(top.paquet, top.cve_p1, color="#c00000", label="P1 (KEV)")
ax.barh(top.paquet, top.cve_p2, left=top.cve_p1, color="#ed7d31", label="P2")
ax.barh(top.paquet, top.nb_cve - top.cve_urgentes, left=top.cve_urgentes, color="#d9d9d9", label="P3 / P4")
for i, r in top.iterrows():
    ax.text(r.nb_cve + top.nb_cve.max() * 0.01, i, f"{r.nb_postes} poste{'s' if r.nb_postes > 1 else ''}", va="center", fontsize=8, color="#444")
ax.invert_yaxis(); ax.set_xlabel("Nombre de CVE"); ax.legend(loc="lower right")
ax.set_xlim(0, top.nb_cve.max() * 1.2)
ax.set_title("Quinze paquets à mettre à jour en priorité (KEV d'abord, puis volume)")
fig.text(0.01, 0.01, foot, fontsize=8, color="#666"); fig.tight_layout(rect=(0, 0.03, 1, 1))
fig.savefig(OUT / "top15_paquets.png", dpi=150); print("top15_paquets.png")
