resource "aws_iam_user" "admin_user" {
  name = "admin-user"
}

resource "aws_iam_access_key" "insecure_key" {
  # CRITICAL FLAW: Generating long-lived access keys instead of using IAM Roles
  user = aws_iam_user.admin_user.name
}