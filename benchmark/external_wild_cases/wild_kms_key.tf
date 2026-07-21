# wild_kms_key.tf
# Source pattern: open-source security & key management infrastructure module.
# Misconfigurations: enable_key_rotation = false, policy contains wildcard principal "*",
# short deletion window (7 days), bypass_policy_lockout_safety_check = false.

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# Primary master key for data encryption.
# MISCONFIGURATION: enable_key_rotation = false; annual key rotation disabled.
# MISCONFIGURATION: policy allows Principal = "*" full kms:* access.
resource "aws_kms_key" "master_data_key" {
  description             = "KMS Master Key for Data Lake Encryption"
  deletion_window_in_days = 7      # MISCONFIGURATION: short deletion window (7 days).
  enable_key_rotation     = false  # MISCONFIGURATION: key rotation disabled.
  is_enabled              = true

  # MISCONFIGURATION: Overly permissive key policy granting wildcard kms:* permissions to any principal in account/world.
  policy = jsonencode({
    Version = "2012-10-17"
    Id      = "insecure-key-policy"
    Statement = [
      {
        Sid       = "Enable IAM User Permissions"
        Effect    = "Allow"
        Principal = {
          AWS = "*"  # MISCONFIGURATION: Wildcard principal allows unauthenticated/external access.
        }
        Action    = "kms:*"
        Resource  = "*"
      }
    ]
  })

  tags = {
    Environment = "production"
    ManagedBy   = "terraform"
  }
}

resource "aws_kms_alias" "master_data_key_alias" {
  name          = "alias/production-master-data-key"
  target_key_id = aws_kms_key.master_data_key.key_id
}

# Secondary application secrets KMS key.
resource "aws_kms_key" "secrets_key" {
  description             = "KMS Key for App Secrets"
  deletion_window_in_days = 10
  enable_key_rotation     = false  # MISCONFIGURATION: key rotation disabled.

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowAllAppRoles"
        Effect    = "Allow"
        Principal = "*"
        Action    = [
          "kms:Decrypt",
          "kms:GenerateDataKey*"
        ]
        Resource  = "*"
      }
    ]
  })
}

output "master_key_arn" {
  value = aws_kms_key.master_data_key.arn
}

output "secrets_key_arn" {
  value = aws_kms_key.secrets_key.arn
}
