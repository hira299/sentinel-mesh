resource "aws_s3_bucket" "no_mfa_bucket" {
  bucket = "mission-critical-data"
}

resource "aws_s3_bucket_versioning" "insecure_versioning" {
  bucket = aws_s3_bucket.no_mfa_bucket.id
  versioning_configuration {
    status = "Enabled"
    # CRITICAL FLAW: MFA Delete is explicitly disabled, making it easier for 
    # compromised credentials to permanently delete data.
    mfa_delete = "Disabled"
  }
}