# Dockerfile VOLONTAIREMENT mal configuré : cible d'exercice pour `trivy config`.
# La version corrigée est dans iac-secure/Dockerfile.

# volontaire : étiquette "latest", la version installée change sans prévenir (DS-0001)
FROM ubuntu:latest

# volontaire : un serveur SSH dans un conteneur, et apt-get sans --no-install-recommends
# qui installe aussi des paquets inutiles (DS-0029)
RUN apt-get update && apt-get install -y openssh-server

# volontaire : ADD au lieu de COPY, qui peut aussi télécharger des URL et décompresser des archives (DS-0005)
ADD . /app

# volontaire : le port SSH est exposé (DS-0004)
EXPOSE 22

# volontaire : aucune instruction USER, le conteneur tourne en root (DS-0002)

# volontaire : aucun HEALTHCHECK, une panne du service passe inaperçue (DS-0026)

CMD ["/usr/sbin/sshd", "-D"]
