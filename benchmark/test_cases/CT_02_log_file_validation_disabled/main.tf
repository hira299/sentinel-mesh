resource "aws_cloudtrail" "unvalidated_trail" {
  name                          = "unvalidated-trail"
  s3_bucket_name                = "my-log-bucket"
  
  # CRITICAL FLAW: Log file integrity validation is disabled. 
  # An attacker could modify or delete logs without being detected.
  enable_log_file_validation    = false
}