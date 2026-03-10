resource "aws_ecr_repository" "no_lifecycle" {
  name = "bloated-repo"
}

# CRITICAL FLAW: An ECR repository is created without an aws_ecr_lifecycle_policy.
# This allows old, potentially vulnerable images to persist indefinitely, 
# increasing the attack surface and costs.