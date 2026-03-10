resource "aws_wafv2_web_acl" "permissive_waf" {
  name        = "permissive-waf"
  scope       = "REGIONAL"

  # CRITICAL FLAW: Default action is set to Allow. 
  # If a rule is misconfigured or fails, all traffic is let through by default.
  default_action {
    allow {}
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "permissive-waf"
    sampled_requests_enabled   = true
  }
}