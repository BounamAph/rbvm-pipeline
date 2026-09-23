# Parc : chiffres clés

Sources : scans Trivy du 2026-09-23 (8 postes), CISA KEV 2026-09-21, FIRST EPSS 2026-09-21.

## Entonnoir
- Détections brutes : **8,144** (+ 87 identifiants hors CVE, GHSA/DLA, mis de côté)
- CVE uniques : **2,020**  (ratio 4.0 détections par CVE : c'est la duplication entre postes)
- Paquets concernés : **138** paquets source (372 paquets binaires : plusieurs binaires d'une même source se corrigent par une seule mise à jour)
- Paquets portant au moins une CVE P1 ou P2 : **77**
- Mises à part : **9,372** détections de noyau (8,966 CVE). Dans un conteneur le noyau vient de l'hôte ; sur un parc classique c'est une action d'infrastructure avec redémarrage, pas une campagne applicative. Suivies dans `output/noyau.csv`.
- Détections par poste : {'debian:9': 71, 'nginx:1.16': 363, 'node:12': 582, 'postgres:10': 231, 'python:3.7': 13380, 'tomcat:8.5.50': 686, 'ubuntu:18.04': 0, 'wordpress:5.4': 2290}
- **Postes sans aucune détection : ubuntu:18.04** : distribution en fin de vie, le scanner n'a plus de flux de sécurité. Zéro ne veut pas dire sain, mais aveugle → à traiter en migration, hors pipeline.

## Répartition RBVM des CVE uniques
P1 (KEV) : 8 · P2 : 361 · P3 : 712 · P4 : 939
- Système / applicatif : {'système': 1790, 'applicatif': 229, 'mixte': 1}
- CVE sans correctif disponible : 705 (34.9 %), dont 61 urgentes → remplacement, contournement ou acceptation

## Exposition
- Postes exposés à Internet (data/exposition.json) : nginx:1.16, wordpress:5.4
- CVE relevées d'un niveau parce qu'exploitables à distance sur un poste exposé : **256** (P3 → P2 : 128 · P4 → P3 : 128)
- CVE urgentes (P1 + P2) présentes sur un poste exposé à Internet : **235** sur 369

## Voie rapide (P1 + P2)
- 369 CVE à traiter hors cycle, sur 661 couples (poste, CVE)
- Dont KEV liées à des rançongiciels : 1

## Campagnes : le chiffre clé
**Mettre à jour les 10 premiers paquets ferme 139 des 369 CVE urgentes (37.7 %) et 476 CVE au total (23.6 %).**

Top 10 :
|   rang | paquet                            | famille    |   nb_postes |   nb_cve |   cve_p1 |   cve_p2 | correctif_dispo   |
|-------:|:----------------------------------|:-----------|------------:|---------:|---------:|---------:|:------------------|
|      1 | freetype                          | système    |           5 |        5 |        2 |        3 | oui               |
|      2 | apache2                           | système    |           1 |       40 |        1 |       36 | oui               |
|      3 | libwebp                           | système    |           3 |       13 |        1 |       12 | oui               |
|      4 | org.apache.tomcat:tomcat-catalina | applicatif |           1 |       25 |        1 |       11 | oui               |
|      5 | glibc                             | système    |           4 |       56 |        1 |        9 | oui               |
|      6 | org.apache.tomcat:tomcat-coyote   | applicatif |           1 |       16 |        1 |        8 | oui               |
|      7 | git                               | système    |           3 |       30 |        1 |        6 | oui               |
|      8 | nghttp2                           | système    |           3 |        5 |        1 |        2 | oui               |
|      9 | imagemagick                       | système    |           3 |      219 |        0 |       22 | oui               |
|     10 | openssl                           | système    |           6 |       68 |        0 |       22 | oui               |

## Phrase d'entretien
« Sur 8,144 détections, 2,020 CVE uniques et 138 paquets. Deux files : une file conformité par volume, une voie rapide de 369 CVE exploitées ou probablement exploitables. Mettre à jour 10 paquets ferme 37.7 % des urgentes. »
« Une CVE sans correctif ne s'ignore pas, elle change de file : elle passe de la campagne de patching au plan de migration ou à l'acceptation de risque. »
