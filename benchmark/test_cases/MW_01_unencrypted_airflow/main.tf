resource "aws_mwaa_environment" "unencrypted_mwaa" {
  name               = "insecure-airflow"
  execution_role_arn = "arn:aws:iam::123456789012:role/mwaa-role"
  network_configuration {
    security_group_ids = ["sg-12345"]
    subnet_ids         = ["subnet-12345", "subnet-67890"]
  }
  source_bucket_arn = "arn:aws:s3:::my-airflow-bucket"
  dag_s3_path      = "dags"

  # CRITICAL FLAW: kms_key is missing, data at rest is not encrypted with a CMK
}