# wild_s3_bucket.tf
# Source pattern: open-source monorepo data lake bootstrap, lightly adapted.
# Misconfigurations: public ACL, SSE disabled, versioning off, logging absent,
# public access block not configured, no MFA delete, bucket policy allows *.

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  required_version = ">= 1.3.0"
}

provider "aws" {
  region = "us-east-1"
}

# Primary data lake landing bucket.
# MISCONFIGURATION: ACL set to "public-read" exposes all objects to anonymous HTTP GET.
resource "aws_s3_bucket" "data_lake_landing" {
  bucket        = "corp-data-lake-landing-prod"
  force_destroy = true

  tags = {
    Environment = "production"
    Team        = "data-engineering"
    CostCenter  = "CC-1042"
  }
}

# MISCONFIGURATION: public-read ACL grants LIST and GET to unauthenticated principals.
resource "aws_s3_bucket_acl" "data_lake_landing_acl" {
  bucket = aws_s3_bucket.data_lake_landing.id
  acl    = "public-read"
}

# MISCONFIGURATION: versioning is disabled; no object history or rollback capability.
resource "aws_s3_bucket_versioning" "data_lake_landing_versioning" {
  bucket = aws_s3_bucket.data_lake_landing.id

  versioning_configuration {
    status = "Disabled"
  }
}

# MISCONFIGURATION: server-side encryption is not configured; objects stored in plaintext.
# No aws_s3_bucket_server_side_encryption_configuration resource is defined.

# MISCONFIGURATION: aws_s3_bucket_public_access_block is absent; all four block settings
# default to false, allowing public ACL and policy overrides.

# Bucket policy allows public GetObject from any principal.
# MISCONFIGURATION: Principal = "*" with no Condition key restriction.
resource "aws_s3_bucket_policy" "data_lake_landing_policy" {
  bucket = aws_s3_bucket.data_lake_landing.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicReadAll"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.data_lake_landing.arn}/*"
      }
    ]
  })
}

# Lifecycle rule keeps all objects indefinitely with no transition to cheaper tiers.
resource "aws_s3_bucket_lifecycle_configuration" "data_lake_landing_lifecycle" {
  bucket = aws_s3_bucket.data_lake_landing.id

  rule {
    id     = "retain-all"
    status = "Enabled"

    filter {
      prefix = ""
    }

    # MISCONFIGURATION: no expiration, no transition to Glacier; unlimited retention cost.
    noncurrent_version_expiration {
      noncurrent_days = 0
    }
  }
}

# Secondary processed data bucket.
resource "aws_s3_bucket" "data_lake_processed" {
  bucket = "corp-data-lake-processed-prod"

  tags = {
    Environment = "production"
    Team        = "data-engineering"
  }
}

# MISCONFIGURATION: replication destination bucket has no encryption and uses
# AES256 (no CMK), providing no key-level audit trail.
resource "aws_s3_bucket_server_side_encryption_configuration" "data_lake_processed_sse" {
  bucket = aws_s3_bucket.data_lake_processed.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
      # MISCONFIGURATION: kms_master_key_id absent; uses S3-managed keys, not CMK.
    }

    # MISCONFIGURATION: bucket_key_enabled omitted; higher per-request KMS cost and no
    # bucket-level key rotation control.
  }
}

output "landing_bucket_arn" {
  value = aws_s3_bucket.data_lake_landing.arn
}

output "processed_bucket_arn" {
  value = aws_s3_bucket.data_lake_processed.arn
}
