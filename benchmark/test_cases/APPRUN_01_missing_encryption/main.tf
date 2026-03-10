resource "aws_apprunner_service" "unencrypted_service" {
  service_name = "insecure-app"

  source_configuration {
    image_repository {
      image_identifier      = "public.ecr.aws/aws-containers/hello-app-runner:latest"
      image_repository_type = "ECR_PUBLIC"
    }
  }

  # CRITICAL FLAW: encryption_configuration block is missing.
  # Data at rest will be encrypted with AWS-managed keys instead of Customer Managed Keys (CMK).
}