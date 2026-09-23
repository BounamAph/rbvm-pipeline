# Version corrigée de iac/Dockerfile : chaque constat Trivy traité.

# Corrige DS-0001 : version figée ("slim" = image minimale, donc moins de paquets et moins de CVE).
# Encore plus strict : figer l'empreinte, par exemple python:3.12-slim@sha256:...
FROM python:3.12-slim

# Corrige DS-0029 : --no-install-recommends n'installe que le strict nécessaire,
# et on vide le cache apt pour alléger l'image.
# Plus de serveur SSH : on n'administre pas un conteneur en SSH, on le reconstruit.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# Corrige DS-0002 : un utilisateur dédié, sans privilèges.
RUN useradd --create-home --shell /usr/sbin/nologin app

WORKDIR /app

# Corrige DS-0005 : COPY copie des fichiers locaux, sans téléchargement ni décompression cachés.
COPY --chown=app:app . /app

USER app

# Corrige DS-0004 : plus de port 22, seulement le port du service web.
EXPOSE 8080

# Corrige DS-0026 : Docker ou Kubernetes peuvent détecter un service en panne et le redémarrer.
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD curl -fsS http://localhost:8080/ || exit 1

CMD ["python", "-m", "http.server", "8080"]
