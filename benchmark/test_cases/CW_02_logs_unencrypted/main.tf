resource "aws_cloudwatch_log_group" "unencrypted_logs" {
  name = "sensitive-app-logs"
  # CRITICAL FLAW: kms_key_id is not provided, 
  # logs are encrypted with default keys rather than Customer Master Keys (CMK)
}