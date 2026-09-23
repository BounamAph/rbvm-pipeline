"""Détections → CVE uniques → enrichissement KEV/EPSS → niveaux P1–P4 → regroupement par paquet → campagnes.

Entrées : data/detections.parquet, data/kev.parquet, data/epss.parquet, (optionnel) data/nvd.parquet,
          (optionnel) data/exposition.json : exposition réseau de chaque poste, qui relève d'un niveau les CVE exposées
Sorties : output/cve_uniques.parquet, output/paquets.csv, output/voie_rapide.csv, output/campagnes.csv
          output/ecarts_cvss.csv (si nvd.parquet présent), output/parc_stats.md, output/RBVM_parc.xlsx (6 onglets)
"""
import json
import pandas as pd
from common import DATA, OUT, stamps

det = pd.read_parquet(DATA / "detections.parquet")
kev = pd.read_parquet(DATA / "kev.parquet")
epss = pd.read_parquet(DATA / "epss.parquet")
nvd_path = DATA / "nvd.parquet"
nvd = pd.read_parquet(nvd_path)[["cve_id", "cvss", "cvss_severite"]].rename(
    columns={"cvss": "cvss_nvd", "cvss_severite": "severite_nvd"}) if nvd_path.exists() else None

pj0 = json.loads((DATA / "postes.json").read_text()) if (DATA / "postes.json").exists() else {}
NB_POSTES = len(pj0.get("postes", {})) or det.poste.nunique()
d = det[det.est_cve].copy()
hors_cve = det[~det.est_cve]
# Le noyau est suivi à part : il ne se corrige pas par une mise à jour de l'image (conteneur) ni par le
# catalogue applicatif (parc classique) — c'est une action d'infrastructure, avec redémarrage.
noyau = d[d.est_noyau]
d = d[~d.est_noyau].copy()

# Exposition réseau de chaque poste : déclarée à la main dans data/exposition.json (mini-CMDB : internet, interne, aucun).
# Un poste absent du fichier est « inconnu » et ne déclenche aucune remontée de niveau : on ne suppose pas l'exposition.
expo_path = DATA / "exposition.json"
expo = {p: v["exposition"] for p, v in json.loads(expo_path.read_text(encoding="utf-8")).items()
        if not p.startswith("_")} if expo_path.exists() else {}
d["exposition"] = d.poste.map(expo).fillna("inconnu")
inconnus = sorted(set(d.poste) - set(expo))
if inconnus:
    print(f"NOTE : exposition non déclarée pour {', '.join(inconnus)} (data/exposition.json) → traités comme non exposés")

# ---------------------------------------------------------------- 1. CVE uniques : une ligne par CVE, avec son empreinte sur le parc
cve = d.groupby("cve_id").agg(
    cvss_scanner=("cvss_scanner", "max"),
    severite_scanner=("severite_scanner", "first"),
    acces_reseau=("acces_reseau", "max"),
    nb_postes=("poste", "nunique"),
    nb_detections=("cve_id", "size"),
    nb_paquets=("paquet_source", "nunique"),
    paquets=("paquet_source", lambda s: ", ".join(sorted(set(s))[:5])),
    famille=("famille", lambda s: "système" if (s == "système").all() else "applicatif" if (s == "applicatif").all() else "mixte"),
    correctif_dispo=("version_corrigee", lambda s: s.notna().any()),
    date_publication=("date_publication", "min"),
).reset_index()
# Sur combien de postes exposés à Internet la CVE est-elle présente ?
cve = cve.merge(d[d.exposition == "internet"].groupby("cve_id").poste.nunique().rename("nb_postes_internet"),
                on="cve_id", how="left")
cve["nb_postes_internet"] = cve.nb_postes_internet.fillna(0).astype(int)
cve["expose_internet"] = cve.nb_postes_internet > 0

# ---------------------------------------------------------------- 2. enrichissement : KEV, EPSS, NVD (recoupement de criticité)
cve = cve.merge(epss, on="cve_id", how="left").merge(
    kev[["cve_id", "date_kev", "echeance_kev", "rancongiciel"]], on="cve_id", how="left")
cve["dans_kev"] = cve.date_kev.notna()
cve["rancongiciel"] = cve.rancongiciel.fillna(False).astype(bool)
if nvd is not None:
    cve = cve.merge(nvd, on="cve_id", how="left")
    cve["ecart_cvss"] = (cve.cvss_scanner - cve.cvss_nvd).round(1)
    ecarts = cve[cve.ecart_cvss.abs() >= 1.0][["cve_id", "cvss_scanner", "cvss_nvd", "ecart_cvss", "nb_postes"]]
    ecarts.to_csv(OUT / "ecarts_cvss.csv", index=False)      # les criticités incohérentes, tracées, jamais corrigées en silence
    print(f"{len(ecarts)} CVE avec un écart ≥ 1 point entre le scanner et la NVD → output/ecarts_cvss.csv")
cve["cvss"] = cve.cvss_scanner

# ---------------------------------------------------------------- 3. grille RBVM
SEUIL_EPSS = 0.10
def niveau(r):
    if r.dans_kev: return "P1"
    if (pd.notna(r.epss) and r.epss >= SEUIL_EPSS) or (pd.notna(r.cvss) and r.cvss >= 9.0 and r.acces_reseau): return "P2"
    if pd.notna(r.cvss) and r.cvss >= 7.0: return "P3"
    return "P4"
cve["niveau_base"] = cve.apply(niveau, axis=1)

# Exposition : une CVE exploitable à distance (vecteur AV:N) sur un poste joignable depuis Internet monte d'un niveau.
# P1 ne bouge pas (déjà au maximum). Une faille qui demande un accès local ne devient pas plus grave parce que
# la machine est sur Internet : d'où la condition sur le vecteur réseau.
MONTEE = {"P3": "P2", "P4": "P3"}
cve["releve_exposition"] = cve.expose_internet & cve.acces_reseau & cve.niveau_base.isin(["P3", "P4"])
cve["niveau"] = cve.niveau_base.where(~cve.releve_exposition, cve.niveau_base.map(MONTEE))
# Statut de traitement : initialisé par le pipeline, à faire vivre à la main dans le classeur.
# Valeurs possibles : à corriger, corrigé, fin de vie, will not fix, faux positif, non affecté, contourné, accepté
cve["statut"] = cve.correctif_dispo.map({True: "à corriger", False: "fin de vie / sans correctif"})
cve = cve.sort_values(["niveau", "epss", "nb_postes"], ascending=[True, False, False])
cve.to_parquet(OUT / "cve_uniques.parquet", index=False)

# ---------------------------------------------------------------- 4. paquets (= applications) : la vue qui dimensionne une campagne
dn = d.merge(cve[["cve_id", "niveau", "epss", "dans_kev"]], on="cve_id", how="left")
paq = dn.groupby(["paquet_source", "famille"]).agg(
    nb_cve=("cve_id", "nunique"),
    cve_p1=("cve_id", lambda s: dn.loc[s.index].query("niveau == 'P1'").cve_id.nunique()),
    cve_p2=("cve_id", lambda s: dn.loc[s.index].query("niveau == 'P2'").cve_id.nunique()),
    nb_postes=("poste", "nunique"),
    nb_detections=("cve_id", "size"),
    binaires=("paquet", lambda s: ", ".join(sorted(set(s))[:6])),
    nb_binaires=("paquet", "nunique"),
    versions_installees=("version_installee", lambda s: ", ".join(sorted(set(s))[:3])),
    version_corrigee=("version_corrigee", lambda s: max((x for x in s.dropna()), default=None)),
    correctif_dispo=("version_corrigee", lambda s: "oui" if s.notna().any() else "non / fin de vie"),
    epss_max=("epss", "max"),
).reset_index()
paq["cve_urgentes"] = paq.cve_p1 + paq.cve_p2
paq["statut"] = paq.correctif_dispo.map({"oui": "à corriger", "non / fin de vie": "migration / acceptation"})
paq["poids"] = paq.nb_postes * paq.nb_cve                        # tri « hygiène » : volume
# Ordre final : les KEV d'abord (voie rapide), puis le volume. C'est là que le RBVM décide l'ordre des campagnes.
paq = paq.rename(columns={"paquet_source": "paquet"})
paq = paq.sort_values(["cve_p1", "cve_p2", "poids"], ascending=False).reset_index(drop=True)
paq["rang"] = paq.index + 1
paq["cve_urgentes_cumulees_pct"] = (100 * paq.cve_urgentes.cumsum() / max(paq.cve_urgentes.sum(), 1)).round(1)
paq.to_csv(OUT / "paquets.csv", index=False)

# ---------------------------------------------------------------- 5. voie rapide et campagnes
voie = cve[cve.niveau.isin(["P1", "P2"])].sort_values(["niveau", "epss"], ascending=[True, False])[
    ["cve_id", "niveau", "dans_kev", "rancongiciel", "echeance_kev", "epss", "cvss", "nb_postes", "paquets", "correctif_dispo"]]
voie.to_csv(OUT / "voie_rapide.csv", index=False)

# Campagnes du mois : les N premiers paquets avec correctif disponible ; combien de CVE urgentes ça ferme
N = 10
camp = paq[paq.correctif_dispo == "oui"].head(N).copy()
urg_total = cve[cve.niveau.isin(["P1", "P2"])].cve_id.nunique()
urg_fermees = dn[dn.paquet_source.isin(camp.paquet) & dn.niveau.isin(["P1", "P2"])].cve_id.nunique()
cve_fermees = dn[dn.paquet_source.isin(camp.paquet)].cve_id.nunique()
camp["gain_cve_urgentes"] = camp.cve_urgentes
camp["responsable"] = ""; camp["date_cible"] = ""; camp["statut"] = "à planifier"
camp[["rang", "paquet", "famille", "nb_postes", "nb_cve", "cve_p1", "cve_p2", "version_corrigee",
      "gain_cve_urgentes", "responsable", "date_cible", "statut"]].to_csv(OUT / "campagnes.csv", index=False)

noyau.groupby("cve_id").agg(cvss=("cvss_scanner", "max"), nb_postes=("poste", "nunique"),
    correctif=("version_corrigee", lambda s: s.notna().any())).reset_index().merge(
    kev[["cve_id", "date_kev"]], on="cve_id", how="left").merge(epss, on="cve_id", how="left").sort_values(
    "epss", ascending=False).to_csv(OUT / "noyau.csv", index=False)

# ---------------------------------------------------------------- 6. synthèse
st = stamps()
pj = json.loads((DATA / "postes.json").read_text()) if (DATA / "postes.json").exists() else {"postes": {}, "sans_detection": []}
aveugles = pj["sans_detection"]
n_det = len(d); n_cve = len(cve); n_paq = paq.paquet.nunique()
n_bin = d.paquet.nunique()
rep = cve.niveau.value_counts().reindex(["P1", "P2", "P3", "P4"]).fillna(0).astype(int)
sans_fix = cve[~cve.correctif_dispo]
def pct(a, b): return f"{100*a/b:.1f} %" if b else "n/a"
postes_internet = sorted(p for p, e in expo.items() if e == "internet")
rel = cve[cve.releve_exposition]
urg_expo = cve[cve.niveau.isin(["P1", "P2"]) & cve.expose_internet]
md = f"""# Parc : chiffres clés

Sources : scans Trivy du {st.get('trivy',{}).get('fetched','?')} ({NB_POSTES} postes), CISA KEV {st.get('kev',{}).get('fetched','?')}, FIRST EPSS {str(st.get('epss',{}).get('score_date','?'))[:10]}{', NVD ' + st.get('nvd',{}).get('fetched','') if nvd is not None else ''}.

## Entonnoir
- Détections brutes : **{n_det:,}** (+ {len(hors_cve):,} identifiants hors CVE, GHSA/DLA, mis de côté)
- CVE uniques : **{n_cve:,}**  (ratio {n_det / max(n_cve,1):.1f} détections par CVE : c'est la duplication entre postes)
- Paquets concernés : **{n_paq:,}** paquets source ({n_bin:,} paquets binaires : plusieurs binaires d'une même source se corrigent par une seule mise à jour)
- Paquets portant au moins une CVE P1 ou P2 : **{int((paq.cve_urgentes > 0).sum()):,}**
- Mises à part : **{len(noyau):,}** détections de noyau ({noyau.cve_id.nunique():,} CVE). Dans un conteneur le noyau vient de l'hôte ; sur un parc classique c'est une action d'infrastructure avec redémarrage, pas une campagne applicative. Suivies dans `output/noyau.csv`.
- Détections par poste : {pj["postes"]}
{("- **Postes sans aucune détection : " + ", ".join(aveugles) + "** : distribution en fin de vie, le scanner n'a plus de flux de sécurité. Zéro ne veut pas dire sain, mais aveugle → à traiter en migration, hors pipeline.") if aveugles else ""}

## Répartition RBVM des CVE uniques
P1 (KEV) : {rep.P1:,} · P2 : {rep.P2:,} · P3 : {rep.P3:,} · P4 : {rep.P4:,}
- Système / applicatif : {cve.famille.value_counts().to_dict()}
- CVE sans correctif disponible : {len(sans_fix):,} ({pct(len(sans_fix), n_cve)}), dont {int(sans_fix.niveau.isin(['P1','P2']).sum())} urgentes → remplacement, contournement ou acceptation

## Exposition
- Postes exposés à Internet (data/exposition.json) : {", ".join(postes_internet) or "aucun déclaré"}
- CVE relevées d'un niveau parce qu'exploitables à distance sur un poste exposé : **{len(rel):,}** (P3 → P2 : {int((rel.niveau_base == "P3").sum()):,} · P4 → P3 : {int((rel.niveau_base == "P4").sum()):,})
- CVE urgentes (P1 + P2) présentes sur un poste exposé à Internet : **{len(urg_expo):,}** sur {int(cve.niveau.isin(["P1", "P2"]).sum()):,}

## Voie rapide (P1 + P2)
- {urg_total:,} CVE à traiter hors cycle, sur {int(cve[cve.niveau.isin(['P1','P2'])].nb_postes.sum()):,} couples (poste, CVE)
- Dont KEV liées à des rançongiciels : {int(cve[cve.dans_kev & cve.rancongiciel].shape[0])}

## Campagnes : le chiffre clé
**Mettre à jour les {len(camp)} premiers paquets ferme {urg_fermees:,} des {urg_total:,} CVE urgentes ({pct(urg_fermees, urg_total)}) et {cve_fermees:,} CVE au total ({pct(cve_fermees, n_cve)}).**

Top 10 :
{paq.head(10)[['rang','paquet','famille','nb_postes','nb_cve','cve_p1','cve_p2','correctif_dispo']].to_markdown(index=False)}

## Phrase d'entretien
« Sur {n_det:,} détections, {n_cve:,} CVE uniques et {n_paq:,} paquets. Deux files : une file conformité par volume, une voie rapide de {urg_total:,} CVE exploitées ou probablement exploitables. Mettre à jour {len(camp)} paquets ferme {pct(urg_fermees, urg_total)} des urgentes. »
« Une CVE sans correctif ne s'ignore pas, elle change de file : elle passe de la campagne de patching au plan de migration ou à l'acceptation de risque. »
"""
(OUT / "parc_stats.md").write_text(md, encoding="utf-8")
print(md)

# ---------------------------------------------------------------- 7. le classeur à six onglets
xl = OUT / "RBVM_parc.xlsx"
with pd.ExcelWriter(xl, engine="xlsxwriter", datetime_format="yyyy-mm-dd") as w:
    wb = w.book
    hdr = wb.add_format({"bold": True, "bg_color": "#1F3864", "font_color": "white", "border": 1})
    p1 = wb.add_format({"bg_color": "#F8CBAD"}); p2 = wb.add_format({"bg_color": "#FFE699"})
    def sheet(df, name, widths=None, niveau_col=None):
        df.to_excel(w, sheet_name=name, index=False)
        ws = w.sheets[name]
        for i, c in enumerate(df.columns):
            ws.write(0, i, c, hdr)
            try:
                wdt = (widths or {}).get(c, max(10, min(40, int(df[c].astype(str).str.len().quantile(0.9)) + 2)))
            except Exception:
                wdt = 14
            ws.set_column(i, i, wdt)
        ws.freeze_panes(1, 0); ws.autofilter(0, 0, max(len(df), 1), len(df.columns) - 1)
        if niveau_col is not None and len(df):
            col = df.columns.get_loc(niveau_col)
            ws.conditional_format(1, 0, len(df), len(df.columns) - 1, {"type": "formula", "criteria": f'=${chr(65+col)}2="P1"', "format": p1})
            ws.conditional_format(1, 0, len(df), len(df.columns) - 1, {"type": "formula", "criteria": f'=${chr(65+col)}2="P2"', "format": p2})
    # Synthèse en premier : c'est ce que le manager ouvre
    syn = pd.DataFrame({"indicateur": ["Postes scannés", "Détections brutes", "CVE uniques", "Paquets concernés",
                                       "CVE P1 (KEV)", "CVE P2", "CVE P3", "CVE P4", "CVE sans correctif",
                                       "CVE relevées d'un niveau par l'exposition", "CVE urgentes sur un poste exposé à Internet",
                                       f"CVE urgentes fermées par les {len(camp)} premières campagnes", "Part des urgentes fermées"],
                        "valeur": [NB_POSTES, n_det, n_cve, n_paq, rep.P1, rep.P2, rep.P3, rep.P4, len(sans_fix),
                                   len(rel), len(urg_expo),
                                   urg_fermees, pct(urg_fermees, urg_total)]})
    sheet(syn, "Synthese", {"indicateur": 55, "valeur": 14})
    sheet(camp[["rang", "paquet", "famille", "nb_postes", "nb_cve", "cve_p1", "cve_p2", "version_corrigee",
                "gain_cve_urgentes", "responsable", "date_cible", "statut"]], "Campagnes")
    ws = w.sheets["Campagnes"]; ws.data_validation(1, 11, max(len(camp), 1), 11, {"validate": "list", "source": ["à planifier", "en cours", "terminé", "bloqué"]})
    sheet(voie, "Voie_rapide", niveau_col="niveau")
    sheet(paq.drop(columns=["poids"]), "Applications")
    sheet(cve.drop(columns=[c for c in ["cvss_scanner"] if c in cve]), "CVE_uniques", niveau_col="niveau")
    ws = w.sheets["CVE_uniques"]; ci = list(cve.drop(columns=[c for c in ["cvss_scanner"] if c in cve]).columns).index("statut")
    ws.data_validation(1, ci, max(len(cve), 1), ci, {"validate": "list", "source": ["à corriger", "corrigé", "fin de vie / sans correctif", "will not fix", "faux positif", "non affecté", "contourné", "accepté"]})
    sheet(d.drop(columns=["est_cve", "titre"]).merge(cve[["cve_id", "niveau"]], on="cve_id", how="left"), "Detections", niveau_col="niveau")
print(f"classeur : {xl}")
