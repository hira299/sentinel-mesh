resource "aws_cloudtrail" "insecure_trail" {
  name                          = "insecure-trail"
  s3_bucket_name                = "my-log-bucket"
  
  # CRITICAL FLAW: Logging is explicitly turned off
  is_multi_region_trail         = false
  enable_logging                = false
}