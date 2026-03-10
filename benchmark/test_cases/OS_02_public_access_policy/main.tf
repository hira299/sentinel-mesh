resource "aws_opensearch_domain" "public_policy_domain" {
  domain_name    = "exposed-domain"
  engine_version = "OpenSearch_1.1"

  access_policies = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "es:*"
      Principal = "*"
      Effect    = "Allow"
      # CRITICAL FLAW: Access policy allows anyone (Principal *) to perform actions on the domain.
      Resource  = "arn:aws:es:us-east-1:123456789012:domain/exposed-domain/*"
    }]
  })
}