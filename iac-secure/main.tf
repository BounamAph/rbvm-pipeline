# Version corrigée de iac/main.tf : mêmes ressources, chaque constat Trivy traité.
# À comparer ligne à ligne avec la version volontairement mal configurée.

provider "aws" {
  region = "eu-west-3" # Paris
}

# Clé de chiffrement gérée par le client (corrige AWS-0132) :
# on contrôle qui peut l'utiliser, et elle change automatiquement chaque année.
resource "aws_kms_key" "logs" {
  description         = "Chiffrement du bucket rbvm-demo-logs"
  enable_key_rotation = true
}

resource "aws_s3_bucket" "logs" {
  bucket = "rbvm-demo-logs"
}

# Corrige AWS-0086, 0087, 0091, 0093 : les 4 garde-fous d'accès public sont actifs.
resource "aws_s3_bucket_public_access_block" "logs" {
  bucket = aws_s3_bucket.logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Corrige AWS-0132 : chiffrement SSE-KMS avec la clé ci-dessus.
resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.logs.arn
    }
  }
}

# Corrige AWS-0090 : versioning, pour récupérer un objet supprimé ou écrasé (rançongiciel).
resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Corrige AWS-0089 : les accès au bucket sont journalisés dans un bucket d'audit
# (déclaré dans le compte de journalisation central, hors de ce fichier).
resource "aws_s3_bucket_logging" "logs" {
  bucket        = aws_s3_bucket.logs.id
  target_bucket = "rbvm-demo-audit-logs"
  target_prefix = "s3/rbvm-demo-logs/"
}

# Corrige AWS-0107 et AWS-0124 : SSH limité au réseau d'administration, règle décrite.
# (203.0.113.0/24 est une plage réservée à la documentation, RFC 5737.)
# Encore mieux en production : aucun port SSH, et AWS Systems Manager Session Manager.
resource "aws_security_group" "admin_ssh" {
  name        = "admin_ssh"
  description = "SSH depuis le reseau d'administration uniquement"

  ingress {
    description = "SSH depuis le bastion d'administration"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["203.0.113.0/24"]
  }
}

resource "aws_instance" "example" {
  ami                    = "ami-0c55b159cbfafe1f0" # valeur fictive
  instance_type          = "t3.micro"
  vpc_security_group_ids = [aws_security_group.admin_ssh.id]

  # Corrige AWS-0131 : disque système chiffré.
  root_block_device {
    encrypted = true
  }

  # Corrige AWS-0028 : IMDSv2 obligatoire (jeton de session), ce qui bloque le scénario Capital One.
  metadata_options {
    http_tokens   = "required"
    http_endpoint = "enabled"
  }
}
