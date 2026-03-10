resource "aws_wafv2_web_acl" "unlogged_waf" {
  name        = "unlogged-waf"
  scope       = "REGIONAL"
  
  default_action {
    allow {}
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "unlogged-waf"
    sampled_requests_enabled   = true
  }
  # CRITICAL FLAW: No aws_wafv2_web_acl_logging_configuration is associated
}