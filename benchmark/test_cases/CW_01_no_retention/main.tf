resource "aws_cloudwatch_log_group" "infinite_retention" {
  name = "app-logs"

  # CRITICAL FLAW: retention_in_days is missing or set to 0 (Never Expire)
  retention_in_days = 0
}