resource "aws_cloudfront_distribution" "insecure_origin" {
  origin {
    domain_name = "my-private-bucket.s3.amazonaws.com"
    origin_id   = "S3-Private"
    # CRITICAL FLAW: S3 origin used without Origin Access Control (OAC) or OAI.
    # This often means the S3 bucket itself must be public for CloudFront to work.
  }

  enabled = true
  default_cache_behavior {
    target_origin_id       = "S3-Private"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    forwarded_values {
      query_string = false
      cookies { forward = "none" }
    }
  }
  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }
}