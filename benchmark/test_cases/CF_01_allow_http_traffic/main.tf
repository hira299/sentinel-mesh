resource "aws_cloudfront_distribution" "insecure_cf" {
  origin {
    domain_name = "mybucket.s3.amazonaws.com"
    origin_id   = "S3-mybucket"
  }

  enabled = true

  default_cache_behavior {
    allowed_methods  = ["GET", "HEAD"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "S3-mybucket"

    forwarded_values {
      query_string = false
      cookies { forward = "none" }
    }

    # CRITICAL FLAW: Allows insecure HTTP traffic instead of redirecting to HTTPS
    viewer_protocol_policy = "allow-all"
  }

  restrictions {
    geo_restriction { restriction_type = "none" }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }
}