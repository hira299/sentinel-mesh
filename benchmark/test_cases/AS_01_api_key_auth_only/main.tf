resource "aws_appsync_graphql_api" "weak_auth_api" {
  name                = "weak-auth-api"
  # CRITICAL FLAW: Using API_KEY (shared secret) instead of IAM/OIDC
  authentication_type = "API_KEY"
}