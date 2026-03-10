resource "aws_acm_certificate" "wildcard_cert" {
  # CRITICAL FLAW: Using a wildcard certificate (*.domain.com) increases the 
  # blast radius if the private key is compromised, as it can impersonate any subdomain.
  domain_name       = "*.example.com"
  validation_method = "DNS"
}