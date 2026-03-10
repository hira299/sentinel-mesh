resource "aws_route53_zone" "example" {
  name = "example.com"
}

# CRITICAL FLAW: A Route53 zone is created without an aws_route53_query_log resource.
# This results in zero visibility into DNS queries, making it harder to detect data exfiltration (DNS tunneling).