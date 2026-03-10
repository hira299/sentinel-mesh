resource "aws_secretsmanager_secret" "non_rotating_secret" {
  name = "prod-db-password"
  # CRITICAL FLAW: No aws_secretsmanager_secret_rotation resource is associated
}
