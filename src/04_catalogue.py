"""Jointure NVD × EPSS × KEV, grille de priorisation P1–P4, chiffres clés et regroupement par produit.

Entrées : data/nvd.parquet, data/epss.parquet, data/kev.parquet, data/cve_produit.parquet
Sorties : output/catalogue.parquet          une ligne par CVE, enrichie et classée
          output/catalogue_stats.md         les chiffres à dire en entretien, datés
          output/produits.csv               regroupement par (éditeur, produit)
          output/kev_enrichi.csv            les CVE KEV avec CVSS et EPSS (petit fichier, lisible dans un tableur)
"""
import pandas as pd
from common import DATA, OUT, stamps

nvd = pd.read_parquet(DATA / "nvd.parquet")
epss = pd.read_parquet(DATA / "epss.parquet")
kev = pd.read_parquet(DATA / "kev.parquet")
cp = pd.read_parquet(DATA / "cve_produit.parquet")

# ---------------------------------------------------------------- 1. jointures à gauche : on ne perd aucune CVE
cat = nvd.merge(epss, on="cve_id", how="left").merge(kev, on="cve_id", how="left")
cat["dans_kev"] = cat["date_kev"].notna()
cat["rancongiciel"] = cat["rancongiciel"].fillna(False).astype(bool)
# Les KEV absentes de la NVD (rare : CVE très récente) sont ajoutées pour ne pas les perdre
manquantes = kev[~kev.cve_id.isin(nvd.cve_id)]
if len(manquantes):
    add = manquantes.merge(epss, on="cve_id", how="left")
    add["dans_kev"] = True
    cat = pd.concat([cat, add], ignore_index=True)

# ---------------------------------------------------------------- 2. grille RBVM (première règle qui matche)
SEUIL_EPSS = 0.10
def niveau(r):
    if r.dans_kev:
        return "P1"
    if (pd.notna(r.epss) and r.epss >= SEUIL_EPSS) or (pd.notna(r.cvss) and r.cvss >= 9.0 and r.acces_reseau):
        return "P2"
    if pd.notna(r.cvss) and r.cvss >= 7.0:
        return "P3"
    return "P4"
cat["niveau"] = cat.apply(niveau, axis=1)

# Classification CVSS classique, pour comparaison
def sev(s):
    if pd.isna(s): return "Non noté"
    if s >= 9.0: return "Critique"
    if s >= 7.0: return "Élevé"
    if s >= 4.0: return "Moyen"
    return "Faible"
cat["classe_cvss"] = cat["cvss"].map(sev)

cat.to_parquet(OUT / "catalogue.parquet", index=False)

# ---------------------------------------------------------------- 3. les chiffres
n = len(cat); K = cat[cat.dans_kev]; nk = len(K)
crit = cat[cat.classe_cvss == "Critique"]
bruit = crit[~crit.dans_kev & (crit.epss.fillna(0) < 0.01)]
kev_sous7 = K[K.cvss.fillna(0) < 7.0]

strategies = {
    "CVSS ≥ 9 (Critique)":          cat.cvss.fillna(0) >= 9.0,
    "CVSS ≥ 7 (Critique + Élevé)":  cat.cvss.fillna(0) >= 7.0,
    "KEV seul (P1)":                cat.dans_kev,
    "KEV ou EPSS ≥ 0,10 ou (CVSS ≥ 9 et réseau) (P1+P2)": cat.niveau.isin(["P1", "P2"]),
}
charge = pd.DataFrame({
    "strategie": list(strategies),
    "cve_a_traiter": [int(m.sum()) for m in strategies.values()],
    "kev_couvertes_pct": [round(100 * (m & cat.dans_kev).sum() / nk, 1) for m in strategies.values()],
})
charge.to_csv(OUT / "charge_comparee.csv", index=False)

delai = (K.date_kev - K.date_publication).dt.days.dropna()
rans = K[K.rancongiciel]; non_rans = K[~K.rancongiciel]

# ---------------------------------------------------------------- 4. regroupement par produit
# Sur les CVE P1 et P2 : quels produits concentrent le risque ? (longue traîne mesurée sur le monde entier)
urg = cat[cat.niveau.isin(["P1", "P2"])][["cve_id", "niveau"]]
prod = cp.merge(urg, on="cve_id").groupby(["editeur", "produit"]).agg(
    cve_p1=("niveau", lambda s: int((s == "P1").sum())),
    cve_p2=("niveau", lambda s: int((s == "P2").sum())),
).reset_index()
prod["cve_urgentes"] = prod.cve_p1 + prod.cve_p2
prod = prod.sort_values(["cve_p1", "cve_urgentes"], ascending=False)
prod["part_cumulee_p1_pct"] = (100 * prod.cve_p1.cumsum() / max(prod.cve_p1.sum(), 1)).round(1)
prod.to_csv(OUT / "produits.csv", index=False)
top20_p1 = prod.head(20).cve_p1.sum() / max(prod.cve_p1.sum(), 1) * 100

K.sort_values("date_kev", ascending=False)[["cve_id", "kev_editeur", "kev_produit", "date_publication", "date_kev",
    "cvss", "cvss_severite", "epss", "rancongiciel", "niveau"]].to_csv(OUT / "kev_enrichi.csv", index=False)

# ---------------------------------------------------------------- 5. rapport
st = stamps()
def pct(a, b): return f"{100*a/b:.1f} %" if b else "n/a"
md = f"""# Catalogue NVD × KEV × EPSS : chiffres clés

Sources : NVD ({st.get('nvd',{}).get('fetched','?')}, {st.get('nvd',{}).get('years','')}), CISA KEV (version {st.get('kev',{}).get('catalogVersion','?')}, récupéré le {st.get('kev',{}).get('fetched','?')}), FIRST EPSS ({st.get('epss',{}).get('model_version','?')}, score du {str(st.get('epss',{}).get('score_date','?'))[:10]}).

## Volumes
- CVE dans le catalogue : {n:,} (dont {int(cat.cvss.notna().sum()):,} avec un CVSS, {int(cat.epss.notna().sum()):,} avec un EPSS)
- CVE exploitées de façon avérée (KEV) : {nk:,}, soit {pct(nk, n)} du catalogue
- Répartition CVSS : {cat.classe_cvss.value_counts().to_dict()}
- Répartition RBVM : {cat.niveau.value_counts().sort_index().to_dict()}

## 1. Trier par CVSS fait patcher du bruit
- CVE notées Critique (CVSS ≥ 9) : {len(crit):,}
- … dont ni exploitées (hors KEV) ni probablement exploitables (EPSS < 1 %) : {len(bruit):,}, soit **{pct(len(bruit), len(crit))} des Critiques**

## 2. Le seuil CVSS laisse passer des CVE exploitées
- KEV avec un CVSS < 7 : {len(kev_sous7):,}, soit **{pct(len(kev_sous7), nk)} des KEV** (invisibles pour une règle « ≥ 7 »)
- KEV sans CVSS du tout : {int(K.cvss.isna().sum()):,}

## 3. Charge de travail selon la stratégie
{charge.to_markdown(index=False)}

Ratio de charge « CVSS ≥ 7 » / « P1+P2 » : **{charge.cve_a_traiter[1] / max(charge.cve_a_traiter[3],1):.1f} pour 1**

## 4. Délai entre publication NVD et ajout au KEV
- Médiane : {delai.median():.0f} jours ; moyenne : {delai.mean():.0f} jours
- KEV ajoutées le jour même ou avant la publication NVD (délai ≤ 0) : {int((delai <= 0).sum()):,} ({pct(int((delai<=0).sum()), len(delai))})
- KEV ajoutées dans les 15 jours : {pct(int((delai <= 15).sum()), len(delai))} ; dans les 30 jours : {pct(int((delai <= 30).sum()), len(delai))}

## 5. Rançongiciels
- KEV liées à des campagnes de rançongiciel : {len(rans):,} ({pct(len(rans), nk)})
- CVSS moyen : rançongiciel {rans.cvss.mean():.1f} vs autres KEV {non_rans.cvss.mean():.1f} ; EPSS médian : {rans.epss.median():.2f} vs {non_rans.epss.median():.2f}

## 6. Concentration par produit (longue traîne)
- Produits distincts portant au moins une CVE P1 : {int((prod.cve_p1 > 0).sum()):,}
- **Les 20 premiers produits concentrent {top20_p1:.1f} % des CVE P1** (voir output/produits.csv)
- Top 10 :
{prod.head(10)[['editeur','produit','cve_p1','cve_p2']].to_markdown(index=False)}

## Phrases d'entretien
- « {pct(len(bruit), len(crit))} des CVE notées critiques n'ont aucun signe d'exploitation : trier par CVSS, c'est patcher du bruit. »
- « {pct(len(kev_sous7), nk)} des CVE réellement exploitées passent sous le seuil CVSS 7. »
- « KEV d'abord, puis EPSS, puis CVSS : {charge.cve_a_traiter[1] / max(charge.cve_a_traiter[3],1):.0f} fois moins de CVE à traiter qu'avec CVSS ≥ 7, sans rater une seule CVE exploitée. »
- « Vingt produits concentrent {top20_p1:.0f} % des CVE exploitées : le levier, c'est la mise à jour par application, pas la CVE une par une. »
"""
(OUT / "catalogue_stats.md").write_text(md, encoding="utf-8")
print(md)
