resource "aws_s3_bucket" "compliance_bucket" {
  bucket = "immutable-records-bucket"
  
  # CRITICAL FLAW: For a bucket intended for compliance/legal logs, 
  # object_lock_enabled is not set to true, allowing data to be deleted.
  object_lock_enabled = false
}