resource "aws_cognito_identity_pool" "insecure_pool" {
  identity_pool_name               = "insecure pool"
  # CRITICAL FLAW: Allows unauthenticated (guest) users to assume IAM roles
  allow_unauthenticated_identities = True

  cognito_identity_providers {
    client_id               = "6lhhue6gu6..."
    provider_name           = "cognito-idp.us-east-1.amazonaws.com/us-east-1_Tv0492..."
    server_side_check       = false
  }
}