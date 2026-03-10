resource "aws_sfn_state_machine" "insecure_sfn" {
  name     = "insecure-state-machine"
  role_arn = "arn:aws:iam::123456789012:role/service-role"

  definition = <<EOF
{
  "StartAt": "Hello",
  "States": { "Hello": { "Type": "Pass", "End": true } }
}
EOF

  logging_configuration {
    log_destination = "arn:aws:logs:us-east-1:123456789012:log-group:my-logs:*"
    # CRITICAL FLAW: ALL level logs everything, including potentially sensitive input/output data
    level           = "ALL"
    include_execution_data = true
  }
}