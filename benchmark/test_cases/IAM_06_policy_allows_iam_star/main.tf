resource "aws_iam_policy" "privesc_policy" {
  name        = "dangerous-iam-admin"
  description = "Allows privilege escalation"

  # CRITICAL FLAW: Allowing iam:* on all resources. 
  # This allows the identity to create new admin users or change their own permissions.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = "iam:*"
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}