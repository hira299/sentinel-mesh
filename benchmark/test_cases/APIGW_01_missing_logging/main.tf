resource "aws_api_gateway_stage" "insecure_stage" {
  deployment_id = "12345"
  rest_api_id   = "67890"
  stage_name    = "prod"

  # CRITICAL FLAW: access_log_settings block is missing, meaning no audit trail for requests
}