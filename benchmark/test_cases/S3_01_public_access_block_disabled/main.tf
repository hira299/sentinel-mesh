resource "aws_s3_bucket" "my_bucket" {
  bucket = "scholarship-test-bucket"
}

resource "aws_s3_bucket_public_access_block" "my_bucket_access" {
  bucket = aws_s3_bucket.my_bucket.id

  block_public_acls       = false
  block_public_policy     = false
}
