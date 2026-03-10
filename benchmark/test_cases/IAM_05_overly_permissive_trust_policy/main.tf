resource "aws_iam_role" "insecure_trust" {
  name = "insecure-trust-role"

  # CRITICAL FLAW: Trust policy allows 'root' of any account to assume the role 
  # without an ExternalID or specific user restriction.
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = "*" 
        }
      }
    ]
  })
}