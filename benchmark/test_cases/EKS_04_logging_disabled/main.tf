resource "aws_eks_cluster" "unlogged_eks" {
  name     = "unlogged-cluster"
  role_arn = "arn:aws:iam::123456789012:role/eks-role"

  vpc_config {
    subnet_ids = ["subnet-12345", "subnet-67890"]
  }

  # CRITICAL FLAW: Control plane logging (api, audit, authenticator) is missing. 
  # There is no record of who did what within the Kubernetes cluster.
  enabled_cluster_log_types = []
}