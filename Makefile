PY=python3
# Phase A (ce soir) : le parc. Phase B (demain) : le catalogue NVD.
all: parc
sources:
	$(PY) src/02_fetch_kev.py
	$(PY) src/03_fetch_epss.py
parc: sources
	$(PY) src/10_load_trivy.py
	$(PY) src/11_prioritize.py
	$(PY) src/12_report.py
nvd:
	$(PY) src/01_fetch_nvd.py $(NVD_ARGS)
catalogue: sources nvd
	$(PY) src/04_catalogue.py
	$(PY) src/05_graphs_catalogue.py
clean:
	rm -f data/*.parquet data/sources.json output/*
