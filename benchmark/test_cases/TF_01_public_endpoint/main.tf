resource "aws_transfer_server" "public_sftp" {
  identity_provider_type = "SERVICE_MANAGED"
  # CRITICAL FLAW: SFTP server is exposed to the public internet
  endpoint_type          = "PUBLIC"
  protocols             = ["SFTP"]
}