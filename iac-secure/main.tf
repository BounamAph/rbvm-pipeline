# Version corrigée de iac/main.tf : mêmes ressources, chaque constat Trivy traité.
# À comparer ligne à ligne avec la version volontairement mal configurée.

provider "aws" {
  region = "eu-west-3" # Paris
}

# Lit le numéro du compte courant (un bloc "data" lit, il ne crée rien).
data "aws_caller_identity" "current" {}

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

# Corrige AWS-0089 : chaque accès au bucket est journalisé dans le bucket d'audit ci-dessous.
# Exigence AWS : la cible est dans le même compte et la même Région que le bucket surveillé.
# Pour centraliser dans un compte d'archives séparé, on ajouterait une réplication S3
# depuis le bucket d'audit (versioning requis des deux côtés).
resource "aws_s3_bucket_logging" "logs" {
  bucket        = aws_s3_bucket.logs.id
  target_bucket = aws_s3_bucket.audit.id
  target_prefix = "s3/rbvm-demo-logs/" # doit rester identique au préfixe de la politique d'audit

  # Aucune référence ne lie ce bloc à la politique : on déclare l'ordre à la main.
  depends_on = [aws_s3_bucket_policy.audit]
}

# Bucket d'audit : reçoit les journaux d'accès de rbvm-demo-logs.
# Constat accepté (AWS-0089) : pas de journaux sur le bucket de journaux (des journaux sur des journaux).
#trivy:ignore:aws-s3-enable-logging
resource "aws_s3_bucket" "audit" {
  bucket = "rbvm-demo-audit-logs"
}

resource "aws_s3_bucket_public_access_block" "audit" {
  bucket = aws_s3_bucket.audit.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Constat accepté (AWS-0132) : la cible des journaux d'accès n'accepte que SSE-S3,
# pas de clé KMS (exigence AWS) ; une clé gérée par le client y bloquerait la livraison.
#trivy:ignore:aws-s3-encryption-customer-key
resource "aws_s3_bucket_server_side_encryption_configuration" "audit" {
  bucket = aws_s3_bucket.audit.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256" # SSE-S3
    }
  }
}

# Versioning : une suppression laisse l'ancienne version, et il est requis pour une future réplication.
resource "aws_s3_bucket_versioning" "audit" {
  bucket = aws_s3_bucket.audit.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Les ACL sont désactivées sur les nouveaux buckets : le service de journalisation
# reçoit le droit d'écrire par une politique, limitée à notre bucket et à notre compte.
resource "aws_s3_bucket_policy" "audit" {
  bucket = aws_s3_bucket.audit.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "S3ServerAccessLogsPolicy"
        Effect    = "Allow"
        Principal = { Service = "logging.s3.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.audit.arn}/s3/rbvm-demo-logs/*"
        Condition = {
          ArnLike      = { "aws:SourceArn" = aws_s3_bucket.logs.arn }
          StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }
        }
      }
    ]
  })
}

# Corrige AWS-0107 et AWS-0124 : SSH limité au réseau d'administration, règle décrite.
# (203.0.113.0/24 est une plage réservée à la documentation, RFC 5737.)
# Encore mieux en production : aucun port SSH, et AWS Systems Manager Session Manager.
# Descriptions sans apostrophe ni accent : l'API EC2 les refuse (a-z, A-Z, 0-9, espace, ._-:/()#,@[]+=&;{}!$*).
resource "aws_security_group" "admin_ssh" {
  name        = "admin_ssh"
  description = "SSH depuis le reseau admin uniquement"

  ingress {
    description = "SSH depuis le bastion admin"
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
