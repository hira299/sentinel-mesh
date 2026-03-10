resource "aws_kms_key" "insecure_key" {
  description = "KMS key with bad policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable Wide Permissions"
        Effect = "Allow"
        # CRITICAL FLAW: Principal is wildcarded or overly broad
        Principal = {
          AWS = "*"
        }
        Action   = "kms:*"
        Resource = "*"
      }
    ]
  })
}