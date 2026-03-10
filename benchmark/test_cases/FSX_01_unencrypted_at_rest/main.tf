resource "aws_fsx_lustre_file_system" "unencrypted_fsx" {
  storage_capacity            = 1200
  subnet_ids                  = ["subnet-12345"]
  deployment_type             = "SCRATCH_2"
  # CRITICAL FLAW: kms_key_id is missing and default encryption is not enforced,
  # leading to potential lack of control over data-at-rest security.
}