"""Charge les scans Trivy (un JSON par image = un « poste ») en une table de détections.

Entrée : data/raw/trivy/*.json   (trivy image --format json --output <fichier> <image>)
Sortie : data/detections.parquet  une ligne par (poste, paquet, version, CVE)

Une détection = « ce poste a ce paquet dans cette version, et cette version est touchée par cette CVE ».
La même CVE sur trois postes fait trois détections : c'est ce qu'un EDR affiche brut.
"""
import json
from pathlib import Path
import pandas as pd
from common import RAW, DATA, stamp

src = RAW / "trivy"
files = sorted(src.glob("*.json"))
if not files:
    raise SystemExit(f"Aucun scan dans {src}. Lance d'abord : trivy image --format json --output {src}/<nom>.json <image>")


def carte_sources(j):
    """PkgName → SrcName, lu dans Results[].Packages (présent seulement si le scan a été lancé avec --list-all-pkgs).
    Debian/Ubuntu livrent plusieurs binaires par source : apache2, apache2-bin, apache2-data et apache2-utils
    viennent tous de la source « apache2 » et se corrigent par UNE mise à jour. Compter les binaires
    séparément gonfle artificiellement le nombre d'actions à mener."""
    m = {}
    for res in j.get("Results") or []:
        for pkg in res.get("Packages") or []:
            nom, src = pkg.get("Name"), pkg.get("SrcName")
            if nom and src:
                m[nom] = src
    return m


def source_de(v, carte):
    """Paquet SOURCE dont le paquet binaire est issu.
    Debian/Ubuntu livrent plusieurs binaires par source : apache2, apache2-bin, apache2-data, apache2-utils
    viennent tous de la source « apache2 » et se corrigent par UNE mise à jour. Compter les binaires
    séparément gonfle artificiellement le nombre d'actions. Trivy met la source dans le PURL,
    qualificateur upstream= : pkg:deb/debian/apache2-bin@2.4.38?...&upstream=apache2
    """
    nom = v.get("PkgName")
    if nom in carte:
        return carte[nom]
    purl = ((v.get("PkgIdentifier") or {}).get("PURL")) or ""
    if "upstream=" in purl:
        up = purl.split("upstream=", 1)[1].split("&")[0].split("%40")[0].split("@")[0]
        if up:
            return up
    return nom


# Le noyau n'appartient pas à l'image : dans un conteneur il vient de l'hôte, et linux-libc-dev ne contient
# que des en-têtes. Trivy y rattache pourtant toutes les CVE du noyau. On les isole au lieu de les mélanger
# aux paquets applicatifs, sinon elles écrasent tout le classement (elles pèsent souvent plus de 80 % du volume).
NOYAU = {"linux", "linux-libc-dev", "linux-headers", "linux-aws", "linux-azure", "linux-gcp"}


def cvss_of(v):
    """Trivy donne plusieurs notations (nvd, redhat, ghsa…). On prend la NVD v3 en priorité, sinon la première v3 disponible."""
    c = v.get("CVSS") or {}
    for k in ("nvd", *sorted(c)):
        if k in c and c[k].get("V3Score") is not None:
            return c[k]["V3Score"], c[k].get("V3Vector"), k
    for k in c:
        if c[k].get("V2Score") is not None:
            return c[k]["V2Score"], c[k].get("V2Vector"), k + " (v2)"
    return None, None, None


rows, sans_carte = [], []
for f in files:
    j = json.loads(f.read_text(encoding="utf-8"))
    poste = j.get("ArtifactName") or f.stem
    carte = carte_sources(j)
    if not carte:
        sans_carte.append(poste)
    for res in j.get("Results") or []:
        classe = res.get("Class")            # os-pkgs = paquets système, lang-pkgs = bibliothèques applicatives
        for v in res.get("Vulnerabilities") or []:
            score, vec, source = cvss_of(v)
            src = source_de(v, carte)
            noyau = (src in NOYAU) or (v.get("PkgName") or "").startswith("linux-")
            rows.append({
                "poste": poste,
                "cible": res.get("Target"),
                "famille": "noyau (hôte)" if noyau else ("système" if classe == "os-pkgs" else "applicatif"),
                "type_paquet": res.get("Type"),
                "paquet": v.get("PkgName"),
                "paquet_source": src,
                "est_noyau": noyau,
                "version_installee": v.get("InstalledVersion"),
                "version_corrigee": v.get("FixedVersion") or None,
                "cve_id": v.get("VulnerabilityID"),
                "severite_scanner": (v.get("Severity") or "UNKNOWN").capitalize(),
                "cvss_scanner": score, "cvss_vecteur": vec, "cvss_source": source,
                "acces_reseau": bool(vec and "AV:N" in vec),
                "date_publication": (v.get("PublishedDate") or "")[:10] or None,
                "titre": v.get("Title"),
            })

det = pd.DataFrame(rows)
# Seules les CVE nous intéressent ; Trivy remonte aussi des identifiants GHSA/DLA sans CVE, on les garde à part
det["est_cve"] = det.cve_id.str.startswith("CVE-", na=False)
det["date_publication"] = pd.to_datetime(det["date_publication"], errors="coerce")

# Doublons stricts (même poste, même paquet, même version, même CVE) : un scanner peut lister deux fois
# un paquet présent dans deux couches de l'image. On dédoublonne et on le dit.
avant = len(det)
det = det.drop_duplicates(["poste", "paquet", "version_installee", "cve_id"])
print(f"{avant - len(det)} doublons stricts supprimés")

det.to_parquet(DATA / "detections.parquet", index=False)
stamp("trivy", {"postes": len(files), "detections": len(det)})
if sans_carte:
    print(f"NOTE : pas d'inventaire de paquets dans {len(sans_carte)} scan(s) ({', '.join(sans_carte[:4])}…). "
          "Relance les scans avec --list-all-pkgs pour regrouper les binaires par paquet source "
          "(apache2-bin, apache2-data… → apache2). Sans ça, une seule mise à jour compte pour plusieurs actions.")
dc = det[det.est_cve]
print(f"{len(files)} postes, {len(det):,} détections, {dc.cve_id.nunique():,} CVE uniques, "
      f"{det.paquet.nunique():,} paquets binaires → {det.paquet_source.nunique():,} paquets source")
k = dc[dc.est_noyau]
if len(k):
    print(f"dont noyau : {len(k):,} détections, {k.cve_id.nunique():,} CVE. Isolées : dans un conteneur le noyau vient "
          f"de l'hôte, ces CVE ne se corrigent pas en mettant à jour l'image.")
postes = pd.Series({(json.loads(f.read_text(encoding="utf-8")).get("ArtifactName") or f.stem): 0 for f in files})
postes.update(det.groupby("poste").size())
print(postes.astype(int).to_string())
zero = postes[postes == 0].index.tolist()
if zero:
    print(f"ATTENTION : {len(zero)} poste(s) sans aucune détection ({', '.join(zero)}). Sur une distribution en fin de vie, "
          "le scanner n'a plus de flux de sécurité : zéro ne veut pas dire sain, mais aveugle.")
(DATA / "postes.json").write_text(json.dumps({"postes": postes.astype(int).to_dict(), "sans_detection": zero}, indent=2))
