resource "aws_iam_policy" "dangerous_policy" {
  name        = "dangerous-policy"
  description = "A policy that allows everything"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = "*"
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}