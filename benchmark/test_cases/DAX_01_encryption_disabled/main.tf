resource "aws_dax_cluster" "unencrypted_dax" {
  cluster_name       = "unencrypted-cluster"
  iam_role_arn       = "arn:aws:iam::123456789012:role/dax-role"
  node_type          = "dax.r4.large"
  replication_factor = 1

  # CRITICAL FLAW: Cluster side encryption is disabled
  server_side_encryption {
    enabled = false
  }
}