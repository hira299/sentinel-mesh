resource "aws_s3_bucket" "data" {
  bucket = "source-data-bucket"
}

resource "aws_s3_bucket" "inventory" {
  bucket = "inventory-reports-bucket"
}

resource "aws_s3_bucket_inventory" "insecure_inventory" {
  bucket = aws_s3_bucket.data.id
  name   = "EntireBucket"

  destination {
    bucket {
      format     = "CSV"
      bucket_arn = aws_s3_bucket.inventory.arn
      # CRITICAL FLAW: S3 Inventory report is saved without encryption. 
      # This report contains a full list of all objects, metadata, and sizes.
    }
  }
}