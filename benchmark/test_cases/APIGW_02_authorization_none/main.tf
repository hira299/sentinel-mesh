resource "aws_api_gateway_method" "insecure_method" {
  rest_api_id   = "api-123"
  resource_id   = "res-456"
  http_method   = "POST"
  # CRITICAL FLAW: No authorizer defined for a sensitive POST method
  authorization = "NONE"
}