# wild_eks_cluster.tf
# Source pattern: adapted from open-source Kubernetes platform engineering module.
# Misconfigurations: public API server endpoint, no secrets encryption, logging
# disabled, overly permissive node group IAM, no OIDC provider, public node groups.

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-2"
}

resource "aws_iam_role" "eks_cluster_role" {
  name = "eks-cluster-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "eks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "eks_cluster_policy" {
  role       = aws_iam_role.eks_cluster_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}

resource "aws_iam_role" "eks_node_role" {
  name = "eks-node-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "eks_worker_node" {
  role       = aws_iam_role.eks_node_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
}

resource "aws_iam_role_policy_attachment" "eks_cni_policy" {
  role       = aws_iam_role.eks_node_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
}

resource "aws_iam_role_policy_attachment" "eks_ecr_readonly" {
  role       = aws_iam_role.eks_node_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
}

# MISCONFIGURATION: node role also given SSM access and S3 full access without scope.
resource "aws_iam_role_policy_attachment" "eks_node_s3_full" {
  role       = aws_iam_role.eks_node_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
}

resource "aws_eks_cluster" "main" {
  name     = "production-cluster"
  role_arn = aws_iam_role.eks_cluster_role.arn
  version  = "1.28"

  vpc_config {
    subnet_ids              = ["subnet-0aaa1111", "subnet-0bbb2222", "subnet-0ccc3333"]
    security_group_ids      = ["sg-0deadbeef"]

    # MISCONFIGURATION: API server accessible from internet.
    endpoint_public_access  = true
    endpoint_private_access = false

    # MISCONFIGURATION: no public_access_cidrs restriction; any IP can reach API server.
  }

  # MISCONFIGURATION: no encryption_config block; Kubernetes secrets stored in etcd
  # in plaintext without envelope encryption via KMS CMK.

  # MISCONFIGURATION: enabled_cluster_log_types omitted; no control plane logging
  # (api, audit, authenticator, controllerManager, scheduler are all disabled).

  tags = {
    Environment = "production"
    Managed     = "terraform"
  }

  depends_on = [aws_iam_role_policy_attachment.eks_cluster_policy]
}

# MISCONFIGURATION: node group uses public subnets with public IP assignment.
resource "aws_eks_node_group" "general" {
  cluster_name    = aws_eks_cluster.main.name
  node_group_name = "general-nodes"
  node_role_arn   = aws_iam_role.eks_node_role.arn

  # MISCONFIGURATION: nodes placed in public subnets.
  subnet_ids = ["subnet-0aaa1111", "subnet-0bbb2222"]

  scaling_config {
    desired_size = 3
    min_size     = 1
    max_size     = 10
  }

  instance_types = ["m5.large"]
  capacity_type  = "ON_DEMAND"
  disk_size      = 20

  # MISCONFIGURATION: remote_access opens SSH to all sources with no restriction.
  remote_access {
    ec2_ssh_key               = "my-keypair"
    source_security_group_ids = []  # MISCONFIGURATION: empty means all sources allowed.
  }

  update_config {
    max_unavailable = 1
  }

  depends_on = [
    aws_iam_role_policy_attachment.eks_worker_node,
    aws_iam_role_policy_attachment.eks_cni_policy,
    aws_iam_role_policy_attachment.eks_ecr_readonly,
  ]
}

# MISCONFIGURATION: no aws_eks_addon for vpc-cni with IRSA; node-level IAM used instead.
# MISCONFIGURATION: no aws_iam_openid_connect_provider; IRSA cannot be configured.

output "cluster_endpoint" {
  value = aws_eks_cluster.main.endpoint
}

output "cluster_ca" {
  value = aws_eks_cluster.main.certificate_authority[0].data
}
