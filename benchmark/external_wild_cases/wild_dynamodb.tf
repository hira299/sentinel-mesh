# wild_dynamodb.tf
# Source pattern: open-source serverless application database tier.
# Misconfigurations: SSE disabled / default AWS owned key, point-in-time recovery (PITR) disabled,
# deletion protection disabled, continuous backups off, auto-scaling disabled with static capacity.

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

# Main application user session table.
# MISCONFIGURATION: point_in_time_recovery disabled, deletion_protection_enabled = false,
# server_side_encryption enabled = false (or uses default AWS key without CMK).
resource "aws_dynamodb_table" "user_sessions" {
  name           = "production-user-sessions"
  billing_mode   = "PROVISIONED"
  read_capacity  = 20
  write_capacity = 20
  hash_key       = "SessionId"
  range_key      = "UserId"

  attribute {
    name = "SessionId"
    type = "S"
  }

  attribute {
    name = "UserId"
    type = "S"
  }

  attribute {
    name = "CreatedAt"
    type = "N"
  }

  # MISCONFIGURATION: point_in_time_recovery enabled = false; no backup restoration window.
  point_in_time_recovery {
    enabled = false
  }

  # MISCONFIGURATION: server_side_encryption enabled = false; data stored unencrypted or with default key.
  server_side_encryption {
    enabled     = false
    kms_key_arn = null
  }

  # MISCONFIGURATION: deletion_protection_enabled = false; table can be deleted instantly via API/CLI.
  deletion_protection_enabled = false

  global_secondary_index {
    name               = "UserIdIndex"
    hash_key           = "UserId"
    range_key          = "CreatedAt"
    write_capacity     = 10
    read_capacity      = 10
    projection_type    = "ALL"
  }

  ttl {
    attribute_name = "TimeToLive"
    enabled        = false  # MISCONFIGURATION: TTL disabled; expired sessions linger forever.
  }

  tags = {
    Environment = "production"
    Service     = "auth-service"
  }
}

# Secondary order transactions audit table.
resource "aws_dynamodb_table" "order_audit" {
  name         = "production-order-audit"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "OrderId"

  attribute {
    name = "OrderId"
    type = "S"
  }

  # MISCONFIGURATION: missing point_in_time_recovery block entirely.
  # MISCONFIGURATION: missing server_side_encryption block entirely.
  # MISCONFIGURATION: deletion_protection_enabled defaults to false.

  tags = {
    Environment = "production"
    Security    = "audit-log"
  }
}

output "user_sessions_table_arn" {
  value = aws_dynamodb_table.user_sessions.arn
}

output "order_audit_table_arn" {
  value = aws_dynamodb_table.order_audit.arn
}
