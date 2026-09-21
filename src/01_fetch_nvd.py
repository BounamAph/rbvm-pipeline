"""NVD : sévérité (CVSS), vecteur et produits touchés (CPE) pour toutes les CVE publiées.
Source officielle : https://nvd.nist.gov/vuln/data-feeds  (un JSON 2.0 gzippé par année)
Miroir plus rapide : https://github.com/fkie-cad/nvd-json-data-feeds (release quotidienne, même contenu)

Usage :
    python src/01_fetch_nvd.py                # feeds officiels, toutes les années
    python src/01_fetch_nvd.py --mirror       # miroir GitHub (si le CDN NVD est lent)
    python src/01_fetch_nvd.py --from 2020    # seulement 2020 → aujourd'hui (pour un premier test rapide)

Sorties :
    data/nvd.parquet         une ligne par CVE : cvss, vecteur, sévérité, date, produit principal
    data/cve_produit.parquet une ligne par (cve, éditeur, produit) : sert au regroupement par produit
"""
import argparse, gzip, json, lzma, datetime as dt
import pandas as pd
from tqdm import tqdm
from common import RAW, DATA, download, stamp

ap = argparse.ArgumentParser()
ap.add_argument("--mirror", action="store_true", help="utiliser le miroir fkie-cad au lieu de nvd.nist.gov")
ap.add_argument("--from", dest="start", type=int, default=2002)
ap.add_argument("--force", action="store_true", help="retélécharger même si le fichier existe")
args = ap.parse_args()

YEAR_NOW = dt.date.today().year
years = range(args.start, YEAR_NOW + 1)


def url_and_path(y):
    if args.mirror:
        return (f"https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download/CVE-{y}.json.xz",
                RAW / f"CVE-{y}.json.xz")
    return (f"https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{y}.json.gz",
            RAW / f"nvdcve-2.0-{y}.json.gz")


def load_json(path):
    opener = lzma.open if path.suffix == ".xz" else gzip.open
    with opener(path, "rt", encoding="utf-8") as f:
        return json.load(f)


def items(j):
    """Les deux formats ont la même structure de CVE ; seule l'enveloppe change."""
    if "vulnerabilities" in j:            # feed officiel NVD 2.0
        return [v["cve"] for v in j["vulnerabilities"]]
    if "cve_items" in j:                  # miroir fkie-cad
        return j["cve_items"]
    raise ValueError("format de feed inconnu")


def best_cvss(metrics):
    """CVSS v3.1 si présent, sinon v3.0, sinon v2. On garde la version pour être honnête dans les stats."""
    for key, ver in (("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
        lst = metrics.get(key) or []
        if not lst:
            continue
        # Priorité à la notation NVD ("Primary") sur celle de l'éditeur ("Secondary")
        m = next((x for x in lst if x.get("type") == "Primary"), lst[0])
        d = m["cvssData"]
        sev = d.get("baseSeverity") or m.get("baseSeverity")
        return d.get("baseScore"), d.get("vectorString"), (sev or "").upper(), ver
    return None, None, None, None


def cpes(configs):
    """Toutes les paires (éditeur, produit) marquées vulnérables. Un CPE 2.3 s'écrit
    cpe:2.3:<part>:<vendor>:<product>:<version>:... ; part = a (application), o (OS), h (matériel)."""
    out = set()
    for cfg in configs or []:
        for node in cfg.get("nodes", []):
            for m in node.get("cpeMatch", []):
                if not m.get("vulnerable", True):
                    continue
                parts = m["criteria"].split(":")
                if len(parts) >= 5:
                    out.add((parts[2], parts[3], parts[4]))
    return out


rows, prod_rows = [], []
for y in years:
    url, path = url_and_path(y)
    try:
        download(url, path, force=args.force)
    except Exception as e:                # une année absente (ex. 2002 sur le miroir) n'arrête pas le pipeline
        print(f"  {y} : ignoré ({e})")
        continue
    j = load_json(path)
    for c in tqdm(items(j), desc=f"NVD {y}", unit="cve", leave=False):
        if c.get("vulnStatus") in ("Rejected",):
            continue                      # CVE retirées : pas de sens de les prioriser
        score, vec, sev, ver = best_cvss(c.get("metrics") or {})
        prods = cpes(c.get("configurations"))
        # Produit "principal" : le premier par ordre alphabétique, pour avoir une colonne lisible ;
        # le détail complet va dans cve_produit.parquet.
        part, vendor, product = sorted(prods)[0] if prods else (None, None, None)
        rows.append({
            "cve_id": c["id"],
            "date_publication": c.get("published", "")[:10],
            "cvss": score, "cvss_vecteur": vec, "cvss_severite": sev, "cvss_version": ver,
            "acces_reseau": bool(vec and "AV:N" in vec),
            "type_produit": part, "editeur": vendor, "produit": product,
            "nb_produits": len(prods),
        })
        for part, vendor, product in prods:
            prod_rows.append((c["id"], part, vendor, product))

nvd = pd.DataFrame(rows)
nvd["date_publication"] = pd.to_datetime(nvd["date_publication"], errors="coerce")
nvd = nvd.drop_duplicates("cve_id")
nvd.to_parquet(DATA / "nvd.parquet", index=False)

cp = pd.DataFrame(prod_rows, columns=["cve_id", "type_produit", "editeur", "produit"]).drop_duplicates()
cp.to_parquet(DATA / "cve_produit.parquet", index=False)

stamp("nvd", {"source": "fkie-cad mirror" if args.mirror else "nvd.nist.gov", "years": f"{years.start}-{YEAR_NOW}",
              "rows": len(nvd)})
print(f"NVD : {len(nvd)} CVE, {nvd.cvss.notna().sum()} avec CVSS, {len(cp)} liens CVE-produit")
print(nvd.cvss_version.value_counts(dropna=False).to_string())
