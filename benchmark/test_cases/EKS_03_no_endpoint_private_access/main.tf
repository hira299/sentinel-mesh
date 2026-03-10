resource "aws_eks_cluster" "insecure_endpoint" {
  name     = "no-private-access-cluster"
  role_arn = "arn:aws:iam::123456789012:role/eks-role"

  vpc_config {
    subnet_ids = ["subnet-12345", "subnet-67890"]
    endpoint_public_access  = true
    # CRITICAL FLAW: Private access is disabled. 
    # All traffic to the API server, even from within the VPC, must go over the public internet.
    endpoint_private_access = false
  }
}