resource "aws_athena_workgroup" "insecure_workgroup" {
  name = "insecure-athena"

  configuration {
    # CRITICAL FLAW: Allows users to override encryption settings in their queries
    enforce_workgroup_configuration    = false
    publish_cloudwatch_metrics_enabled = true

    result_configuration {
      output_location = "s3://my-athena-results/"
    }
  }
}