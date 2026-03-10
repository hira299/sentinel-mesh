resource "aws_s3_bucket" "unlogged_bucket" {
  bucket = "sensitive-customer-data"
  # CRITICAL FLAW: Server access logging is not configured. 
  # There is no audit trail of who is accessing or downloading objects.
}