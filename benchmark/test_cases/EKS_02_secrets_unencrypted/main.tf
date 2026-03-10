resource "aws_eks_cluster" "insecure_eks_secrets" {
  name     = "unencrypted-secrets-cluster"
  role_arn = "arn:aws:iam::123456789012:role/eks-role"

  vpc_config {
    subnet_ids = ["subnet-12345", "subnet-67890"]
  }

  # CRITICAL FLAW: encryption_config block is missing. 
  # Kubernetes secrets will not be encrypted using AWS KMS.
}