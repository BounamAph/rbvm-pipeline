"""Outils partagés : chemins, téléchargement avec reprise, horodatage des sources."""
from pathlib import Path
import json, datetime as dt
import requests

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data" / "raw"
DATA = ROOT / "data"
OUT = ROOT / "output"
for p in (RAW, DATA, OUT):
    p.mkdir(parents=True, exist_ok=True)

META = DATA / "sources.json"   # date de téléchargement de chaque source, pour dater les chiffres


def download(url: str, dest: Path, force: bool = False) -> Path:
    """Télécharge url vers dest si absent (ou force). Flux par blocs : les feeds NVD font jusqu'à 70 Mo."""
    if dest.exists() and not force:
        print(f"  déjà présent : {dest.name}")
        return dest
    print(f"  téléchargement : {url}")
    with requests.get(url, stream=True, timeout=120, headers={"User-Agent": "rbvm-pipeline/1.0"}) as r:
        r.raise_for_status()
        tmp = dest.with_suffix(dest.suffix + ".part")
        with open(tmp, "wb") as f:
            for chunk in r.iter_content(chunk_size=1 << 20):
                f.write(chunk)
        tmp.rename(dest)
    return dest


def stamp(source: str, extra: dict | None = None) -> None:
    """Enregistre la date de récupération d'une source dans data/sources.json."""
    meta = json.loads(META.read_text()) if META.exists() else {}
    meta[source] = {"fetched": dt.date.today().isoformat(), **(extra or {})}
    META.write_text(json.dumps(meta, indent=2, ensure_ascii=False))


def stamps() -> dict:
    return json.loads(META.read_text()) if META.exists() else {}
