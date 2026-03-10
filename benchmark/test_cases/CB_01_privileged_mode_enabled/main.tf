resource "aws_codebuild_project" "privileged_build" {
  name          = "privileged-project"
  build_timeout = "5"
  service_role  = "arn:aws:iam::123456789012:role/service-role"

  artifacts {
    type = "NO_ARTIFACTS"
  }

  environment {
    compute_type                = "BUILD_GENERAL1_SMALL"
    image                       = "aws/codebuild/standard:4.0"
    type                        = "LINUX_CONTAINER"
    # CRITICAL FLAW: Privileged mode allows container root-level access to the host
    privileged_mode             = true
  }

  source {
    type            = "GITHUB"
    location        = "https://github.com/example/repo.git"
  }
}