# wild_cloudfront.tf
# Source pattern: adapted from open-source SPA hosting and media CDN modules.
# Misconfigurations: allows HTTP, no WAF, no access logging, geo restriction absent,
# S3 origin without OAI/OAC, TLS minimum protocol set to TLSv1, no custom error pages.

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

resource "aws_s3_bucket" "spa_assets" {
  bucket = "corp-spa-frontend-assets"
}

# MISCONFIGURATION: public access block disabled; bucket directly accessible from internet.
resource "aws_s3_bucket_public_access_block" "spa_assets_pab" {
  bucket                  = aws_s3_bucket.spa_assets.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_cloudfront_distribution" "spa_cdn" {
  enabled             = true
  is_ipv6_enabled     = true
  comment             = "SPA frontend CDN"
  default_root_object = "index.html"
  price_class         = "PriceClass_All"

  # MISCONFIGURATION: S3 origin configured as website endpoint without OAI or OAC;
  # any client with the S3 URL can bypass CloudFront entirely.
  origin {
    domain_name = aws_s3_bucket.spa_assets.bucket_regional_domain_name
    origin_id   = "S3-spa-assets"

    # MISCONFIGURATION: no s3_origin_config with origin_access_identity, and no
    # origin_access_control_id; bucket is publicly readable without OAC.
    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "http-only"  # MISCONFIGURATION: origin fetched over HTTP.
      origin_ssl_protocols   = ["TLSv1"]    # MISCONFIGURATION: deprecated TLSv1 protocol.
    }
  }

  default_cache_behavior {
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "S3-spa-assets"

    # MISCONFIGURATION: viewer_protocol_policy = "allow-all" permits HTTP from browsers.
    viewer_protocol_policy = "allow-all"

    forwarded_values {
      query_string = true  # MISCONFIGURATION: query strings forwarded; breaks cache efficiency.
      cookies {
        forward = "all"    # MISCONFIGURATION: all cookies forwarded; cache cannot deduplicate.
      }
    }

    min_ttl     = 0
    default_ttl = 0        # MISCONFIGURATION: zero TTL; every request hits origin (no caching).
    max_ttl     = 0
  }

  # MISCONFIGURATION: no restrictions block; no geo restriction configured.
  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  # MISCONFIGURATION: uses CloudFront default certificate with no custom domain;
  # ssl_support_method = sni-only but minimum_protocol_version uses legacy TLSv1.
  viewer_certificate {
    cloudfront_default_certificate = true
    minimum_protocol_version       = "TLSv1"  # MISCONFIGURATION: deprecated TLS version.
  }

  # MISCONFIGURATION: no logging_config block; no access log delivery to S3.

  # MISCONFIGURATION: no web_acl_id; no WAF association for request filtering.

  tags = {
    Environment = "production"
    Team        = "frontend"
  }
}

# Media CDN with custom origin - additional misconfigurations.
resource "aws_cloudfront_distribution" "media_cdn" {
  enabled         = true
  is_ipv6_enabled = false
  comment         = "Media asset CDN"
  price_class     = "PriceClass_100"

  origin {
    domain_name = "media-api.internal.example.com"
    origin_id   = "MediaAPI"

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "match-viewer"  # MISCONFIGURATION: follows viewer; allows HTTP.
      origin_ssl_protocols   = ["TLSv1", "TLSv1.1", "TLSv1.2"]  # MISCONFIGURATION: TLSv1/1.1 included.
    }
  }

  default_cache_behavior {
    allowed_methods        = ["GET", "HEAD", "OPTIONS"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "MediaAPI"
    viewer_protocol_policy = "allow-all"  # MISCONFIGURATION: HTTP allowed.

    forwarded_values {
      query_string = false
      cookies { forward = "none" }
    }

    min_ttl     = 0
    default_ttl = 3600
    max_ttl     = 86400
  }

  restrictions {
    geo_restriction { restriction_type = "none" }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }
}

output "spa_cdn_domain" {
  value = aws_cloudfront_distribution.spa_cdn.domain_name
}
