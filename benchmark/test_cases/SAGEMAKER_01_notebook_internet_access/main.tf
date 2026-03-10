resource "aws_sagemaker_notebook_instance" "insecure_notebook" {
  name          = "my-notebook"
  role_arn      = "arn:aws:iam::123456789012:role/service-role/AmazonSageMaker-ExecutionRole"
  instance_type = "ml.t2.medium"

  # CRITICAL FLAW: Allows the notebook to connect directly to the internet
  direct_internet_access = "Enabled"
}