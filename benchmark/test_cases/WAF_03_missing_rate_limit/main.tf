resource "aws_wafv2_web_acl" "no_rate_limit" {
  name        = "no-rate-limit-waf"
  scope       = "REGIONAL"
  
  default_action {
    allow {}
  }

  # CRITICAL FLAW: The WAF has no RateBasedStatement. 
  # This leaves the application vulnerable to HTTP flood/DDoS and brute-force attacks.
  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "no-rate-limit"
    sampled_requests_enabled   = true
  }
}