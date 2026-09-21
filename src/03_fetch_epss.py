"""FIRST EPSS : probabilité d'exploitation à 30 jours, par CVE, régénérée chaque jour.
Source : https://www.first.org/epss/data_stats
Sortie : data/epss.parquet."""
import gzip
import pandas as pd
from common import RAW, DATA, download, stamp

URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"

raw = download(URL, RAW / "epss_scores-current.csv.gz", force=True)

# La première ligne du fichier est un commentaire : "#model_version:v2025.03.14,score_date:2026-09-21T00:00:00+0000"
with gzip.open(raw, "rt") as f:
    header = f.readline().strip()
model = dict(kv.split(":", 1) for kv in header.lstrip("#").split(",") if ":" in kv)

df = pd.read_csv(raw, comment="#", dtype={"cve": str, "epss": float, "percentile": float})
df = df.rename(columns={"cve": "cve_id"}).drop_duplicates("cve_id")

df.to_parquet(DATA / "epss.parquet", index=False)
stamp("epss", {**model, "rows": len(df)})
print(f"EPSS : {len(df)} CVE scorées, modèle {model.get('model_version')}, date {model.get('score_date')}")
