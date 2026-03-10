resource "aws_s3_bucket" "no_versioning_bucket" {
  bucket = "no-versioning-bucket"
}

resource "aws_s3_bucket_versioning" "disabled_versioning" {
  bucket = aws_s3_bucket.no_versioning_bucket.id

  versioning_configuration {
    # CRITICAL FLAW: Versioning is not enabled
    status = "Suspended"
  }
}