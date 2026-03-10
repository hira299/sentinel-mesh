resource "aws_secretsmanager_secret" "exposed_secret" {
  name = "sensitive-api-key"
}

resource "aws_secretsmanager_secret_policy" "insecure_policy" {
  secret_arn = aws_secretsmanager_secret.exposed_secret.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowPublicRead"
      Effect    = "Allow"
      # CRITICAL FLAW: Wildcard principal allows all AWS users/accounts to read this secret
      Principal = "*"
      Action    = "secretsmanager:GetSecretValue"
      Resource  = "*"
    }]
  })
}