resource "aws_eks_cluster" "insecure_eks" {
  name     = "public-eks-cluster"
  role_arn = "arn:aws:iam::123456789012:role/eks-service-role"

  vpc_config {
    subnet_ids = ["subnet-12345", "subnet-67890"]
    # CRITICAL FLAW: Endpoint is accessible from the public internet
    endpoint_public_access = true
    endpoint_private_access = false
  }
}