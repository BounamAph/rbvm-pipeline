# Procédure : de zéro au classeur, dans l'ordre

Deux phases. La phase A refait la démarche complète sur un parc (ce soir). La phase B vérifie la règle sur le catalogue mondial (demain, optionnelle).

## 0. Installation (une fois, 10 min)

```bash
unzip rbvm-pipeline.zip && cd rbvm-pipeline
python3 -m venv .venv
source .venv/bin/activate            # Windows PowerShell : .venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Trivy, le scanner qui fabrique les détections (il télécharge les images lui-même, Docker n'est pas nécessaire) :

- Windows : `winget install Aquasecurity.Trivy` puis rouvrir le terminal
- macOS : `brew install trivy`
- Linux : `curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin`

Vérifie : `trivy --version`.

## Phase A : le parc (≈ 45 min, dont 15 de scans)

### A1. Fabriquer les détections : un scan par « poste »

Chaque image de conteneur joue le rôle d'un poste. Des images anciennes donnent des centaines de CVE chacune, et les mêmes CVE reviennent d'une image à l'autre (vrais doublons à dédupliquer).

```bash
mkdir -p data/raw/trivy
for img in ubuntu:18.04 debian:9 node:12 python:3.7 wordpress:5.4 nginx:1.16 tomcat:8.5.50 postgres:10; do
  trivy image --format json --output "data/raw/trivy/$(echo $img | tr ':/' '__').json" "$img"
done
```

PowerShell :

```powershell
mkdir data\raw\trivy -Force
foreach ($img in "ubuntu:18.04","debian:9","node:12","python:3.7","wordpress:5.4","nginx:1.16","tomcat:8.5.50","postgres:10") {
  $name = $img -replace '[:/]','_'
  trivy image --format json --output "data\raw\trivy\$name.json" $img
}
```

Le premier scan télécharge la base de vulnérabilités de Trivy (≈ 50 Mo), les suivants sont rapides. Ajoute ou retire des images à volonté ; 6 à 10, c'est bien.

### A2. Récupérer KEV et EPSS (1 min)

```bash
python src/02_fetch_kev.py      # CISA KEV → data/kev.parquet
python src/03_fetch_epss.py     # FIRST EPSS → data/epss.parquet
```

### A3. Charger, prioriser, dessiner (2 min)

```bash
python src/10_load_trivy.py     # JSON Trivy → data/detections.parquet (1 ligne = poste × paquet × CVE)
python src/11_prioritize.py     # → CVE uniques, KEV/EPSS, niveaux P1–P4, paquets, voie rapide, campagnes, classeur
python src/12_report.py         # → entonnoir.png, top15_paquets.png
```

Ou en une commande : `make parc`.

### A4. Lire le résultat

- `output/parc_stats.md` : l'entonnoir, la répartition P1–P4, et **le chiffre clé** (« mettre à jour N paquets ferme X % des CVE urgentes ») avec la phrase d'entretien.
- `output/RBVM_parc.xlsx`, six onglets dans l'ordre de lecture d'un manager :
  1. `Synthese` : les indicateurs.
  2. `Campagnes` : les 10 paquets du mois, gain attendu, colonnes responsable / date / statut à remplir.
  3. `Voie_rapide` : les CVE P1 et P2 à traiter hors cycle, triées par EPSS, lignes colorées.
  4. `Applications` : un paquet par ligne, nb de CVE, P1/P2, nb de postes, version corrigée, correctif disponible.
  5. `CVE_uniques` : une CVE par ligne, enrichie (KEV, EPSS, CVSS, nb de postes).
  6. `Detections` : le brut, une ligne par (poste, paquet, CVE).
- `output/entonnoir.png`, `output/top15_paquets.png` : les deux graphiques COPIL.
- `output/ecarts_cvss.csv` n'apparaît qu'après la phase B (il compare le CVSS du scanner à celui de la NVD).

### A5. Exercices Excel sur `RBVM_parc.xlsx` (pour la main)

Sur l'onglet `Detections`, refais toi-même :
1. Un tableau croisé « nombre de CVE distinctes par poste » (champ `cve_id` en valeurs, « nombre de valeurs distinctes »).
2. Un tableau croisé « paquets en lignes, niveaux en colonnes, nb de postes en valeurs ».
3. Une colonne `=RECHERCHEX([@cve_id]; CVE_uniques[cve_id]; CVE_uniques[epss])` pour ramener l'EPSS sur chaque détection.
4. Un filtre `niveau = P1` puis un tri par `nb_postes` décroissant : c'est la voie rapide, retrouvée à la main.

### A6. Publier

```bash
git init && git add . && git commit -m "RBVM pipeline : parc Trivy, KEV, EPSS, classeur"
```

Crée le dépôt `rbvm-pipeline` sur GitHub (public), puis `git remote add origin … && git push -u origin main`. Les JSON Trivy et les parquets sont ignorés par git ; les sorties (`output/`) sont versionnées, c'est ce qu'un recruteur regarde. Complète le chiffre clé dans `README.md`.

## Phase B : le catalogue NVD (demain, ≈ 1 h, dont 30 min de téléchargement)

Sert à prouver que la règle tient à l'échelle du monde (280 000 CVE), et à recouper le CVSS du scanner avec celui de la NVD.

```bash
python src/01_fetch_nvd.py --from 2020        # test rapide, 6 fichiers ; --mirror si nvd.nist.gov rame
python src/04_catalogue.py                     # → catalogue_stats.md, produits.csv, charge_comparee.csv
python src/05_graphs_catalogue.py              # → 4 PNG
python src/11_prioritize.py                    # relance : ajoute cvss_nvd, ecart_cvss, ecarts_cvss.csv au parc
```

Puis sans `--from` pour toutes les années, et `make catalogue`.

## Si ça casse

- `Aucun scan dans data/raw/trivy` : les JSON ne sont pas au bon endroit ou le scan a échoué ; relance un `trivy image` seul et regarde le message.
- `ImportError pyarrow` : `pip install pyarrow` dans le venv.
- Téléchargement KEV/EPSS refusé : proxy ou réseau ; télécharge les deux fichiers à la main aux URL indiquées dans les scripts et pose-les dans `data/raw/` avec les mêmes noms, puis relance.
- Colle l'erreur complète telle quelle, on corrige.

## Règle permanente

Aucune donnée, aucun chiffre, aucun nom de mission ou de client, ni dans le code, ni dans le README, ni dans les commits.
