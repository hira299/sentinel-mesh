resource "aws_s3_bucket" "unencrypted_bucket" {
  bucket = "insecure-data-bucket"
  # CRITICAL FLAW: aws_s3_bucket_server_side_encryption_configuration is missing
}
