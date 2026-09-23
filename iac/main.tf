# Terraform VOLONTAIREMENT mal configuré : cible d'exercice pour `trivy config`.
# Rien n'est déployé ; la version corrigée est dans iac-secure/main.tf.

provider "aws" {
  region = "eu-west-3" # Paris
}

# volontaire : bucket sans chiffrement par clé gérée (KMS), sans versioning et sans journalisation
# des accès (AWS-0132, AWS-0090, AWS-0089)
resource "aws_s3_bucket" "logs" {
  bucket = "rbvm-demo-logs"
}

# volontaire : les 4 garde-fous d'accès public sont désactivés, rien n'empêche de rendre
# le bucket lisible par tout Internet (AWS-0086, 0087, 0091, 0093)
resource "aws_s3_bucket_public_access_block" "logs" {
  bucket = aws_s3_bucket.logs.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# volontaire : SSH ouvert à tout Internet, règle sans description (AWS-0107, AWS-0124)
resource "aws_security_group" "allow_ssh" {
  name        = "allow_ssh"
  description = "Allow SSH inbound traffic"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# volontaire : la machine exposée par la règle SSH ci-dessus a un disque non chiffré (AWS-0131)
# et accepte IMDSv1, le maillon de l'attaque Capital One en 2019 (AWS-0028)
resource "aws_instance" "example" {
  ami                    = "ami-0c55b159cbfafe1f0" # valeur fictive
  instance_type          = "t3.micro"
  vpc_security_group_ids = [aws_security_group.allow_ssh.id]

  root_block_device {
    encrypted = false
  }

  metadata_options {
    http_tokens = "optional"
  }
}
