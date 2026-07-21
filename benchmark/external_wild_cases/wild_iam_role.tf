# wild_iam_role.tf
# Source pattern: adapted from open-source CI/CD pipeline Terraform module.
# Misconfigurations: wildcard Action/Resource in inline policy, AdministratorAccess
# managed policy attachment, trust policy without Condition constraints, no
# permissions boundary, hardcoded external account trust without ExternalId.

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

# Deploy role for CI/CD pipeline.
# MISCONFIGURATION: trust policy allows any principal in the account to assume,
# with no Condition key restricting the MFA or source IP.
resource "aws_iam_role" "cicd_deploy_role" {
  name                 = "cicd-deploy-role"
  max_session_duration = 43200  # 12 hours - MISCONFIGURATION: excessively long session.
  path                 = "/"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::123456789012:root" }  # MISCONFIGURATION: entire account root.
        Action    = "sts:AssumeRole"
        # MISCONFIGURATION: no Condition block; no MFA, no ExternalId, no source IP.
      }
    ]
  })

  tags = {
    Team = "devops"
  }
}

# MISCONFIGURATION: attaches AWS managed AdministratorAccess - full account permissions.
resource "aws_iam_role_policy_attachment" "cicd_admin" {
  role       = aws_iam_role.cicd_deploy_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# Inline policy with wildcard Action and wildcard Resource.
# MISCONFIGURATION: effectively grants unrestricted access to all AWS services.
resource "aws_iam_role_policy" "cicd_inline_wild" {
  name = "cicd-wildcard-policy"
  role = aws_iam_role.cicd_deploy_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"        # MISCONFIGURATION: wildcard action - all AWS API operations.
        Resource = "*"        # MISCONFIGURATION: wildcard resource - all AWS resources.
      }
    ]
  })
}

# Lambda execution role.
resource "aws_iam_role" "lambda_exec_role" {
  name = "lambda-exec-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "lambda.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

# MISCONFIGURATION: grants broad S3 and DynamoDB access with wildcard resource
# rather than scoping to specific bucket/table ARNs.
resource "aws_iam_role_policy" "lambda_exec_policy" {
  name = "lambda-exec-policy"
  role = aws_iam_role.lambda_exec_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:*",           # MISCONFIGURATION: all S3 actions, including DeleteBucket.
          "dynamodb:*",     # MISCONFIGURATION: all DynamoDB actions, including DeleteTable.
          "logs:*",
          "ec2:*",          # MISCONFIGURATION: Lambda should not have EC2 API access.
          "iam:PassRole",   # MISCONFIGURATION: iam:PassRole without resource scope.
          "iam:CreateRole", # MISCONFIGURATION: Lambda can escalate privileges.
        ]
        Resource = "*"
      }
    ]
  })
}

# Cross-account role - MISCONFIGURATION: no ExternalId condition; vulnerable to
# confused deputy attacks from any principal in the trusted account.
resource "aws_iam_role" "cross_account_role" {
  name = "cross-account-data-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::999888777666:root" }
        Action    = "sts:AssumeRole"
        # MISCONFIGURATION: missing sts:ExternalId Condition.
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "cross_account_s3" {
  role       = aws_iam_role.cross_account_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"  # MISCONFIGURATION: full S3 access.
}

output "deploy_role_arn" {
  value = aws_iam_role.cicd_deploy_role.arn
}
