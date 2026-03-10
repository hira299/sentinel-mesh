resource "aws_efs_file_system" "unencrypted_efs" {
  creation_token = "my-efs"

  # CRITICAL FLAW: encryption is explicitly set to false
  encrypted = false
}