resource "aws_ses_configuration_set" "insecure_ses" {
  name = "insecure-configuration-set"

  # CRITICAL FLAW: TLS policy set to Optional instead of Require
  delivery_options {
    tls_policy = "Optional"
  }
}