resource "aws_kms_key" "non_rotating_key" {
  description             = "KMS key without rotation"
  deletion_window_in_days = 10
  
  # CRITICAL FLAW: Automatic yearly rotation of the key material is disabled.
  enable_key_rotation     = false
}