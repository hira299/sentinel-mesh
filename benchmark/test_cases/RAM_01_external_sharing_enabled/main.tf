resource "aws_ram_resource_share" "insecure_share" {
  name                      = "insecure-resource-share"
  # CRITICAL FLAW: Allows sharing resources with AWS accounts outside 
  # of the current AWS Organization.
  allow_external_principals = true
}