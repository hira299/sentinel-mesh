resource "aws_workspaces_workspace" "unencrypted_workspace" {
  directory_id = "d-9067323456"
  bundle_id    = "wsb-bh8rs4v79"
  user_name    = "john.doe"

  # CRITICAL FLAW: Root volume encryption is disabled
  root_volume_encryption_enabled = false
}