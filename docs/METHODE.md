# Méthode

## Pourquoi trois sources
- **CVSS** mesure la gravité technique d'une faille si elle est exploitée. Il ne dit rien sur la probabilité qu'elle le soit.
- **KEV** (CISA) liste les CVE dont l'exploitation est constatée. C'est le signal le plus fiable, mais il arrive après coup.
- **EPSS** (FIRST) estime chaque jour la probabilité d'exploitation dans les 30 jours à partir de signaux observés (exploits publics, mentions, scanners). Il anticipe ce que KEV constate.

## Grille
KEV → P1 ; sinon EPSS ≥ 0,10 ou (CVSS ≥ 9 et AV:N) → P2 ; sinon CVSS ≥ 7 → P3 ; sinon P4. Le seuil EPSS 0,10 est celui recommandé par le FIRST comme point de départ ; il se règle selon la capacité de l'équipe.

## Ce que le pipeline vérifie
1. Part des CVE « Critique » sans aucun signe d'exploitation.
2. Part des KEV sous le seuil CVSS 7.
3. Charge de travail et couverture des KEV pour quatre stratégies.
4. Délai publication → KEV.
5. Profil des KEV liées à des rançongiciels.
6. Concentration des CVE urgentes par produit (CPE).

## Choix de traitement
- Jointures à gauche depuis la NVD : aucune CVE n'est supprimée ; les valeurs absentes restent vides.
- CVE au statut « Rejected » exclues.
- Produit principal = premier CPE vulnérable par ordre alphabétique ; le détail complet est dans `cve_produit.parquet`.
