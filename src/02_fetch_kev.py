"""CISA KEV : catalogue des vulnérabilités exploitées de façon avérée.
Source : https://www.cisa.gov/known-exploited-vulnerabilities-catalog
Sortie : data/kev.parquet (une ligne par CVE)."""
import json
import pandas as pd
from common import RAW, DATA, download, stamp

URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

raw = download(URL, RAW / "known_exploited_vulnerabilities.json", force=True)  # change tous les jours
j = json.loads(raw.read_text(encoding="utf-8"))

df = pd.DataFrame(j["vulnerabilities"]).rename(columns={
    "cveID": "cve_id",
    "vendorProject": "kev_editeur",
    "product": "kev_produit",
    "dateAdded": "date_kev",
    "dueDate": "echeance_kev",
    "knownRansomwareCampaignUse": "rancongiciel",
})[["cve_id", "kev_editeur", "kev_produit", "date_kev", "echeance_kev", "rancongiciel"]]

df["date_kev"] = pd.to_datetime(df["date_kev"])
df["echeance_kev"] = pd.to_datetime(df["echeance_kev"])
df["rancongiciel"] = df["rancongiciel"].str.lower().eq("known")   # Known / Unknown → bool
df = df.drop_duplicates("cve_id")

df.to_parquet(DATA / "kev.parquet", index=False)
stamp("kev", {"catalogVersion": j.get("catalogVersion"), "dateReleased": j.get("dateReleased"), "rows": len(df)})
print(f"KEV : {len(df)} CVE, dont {int(df.rancongiciel.sum())} liées à des rançongiciels")
