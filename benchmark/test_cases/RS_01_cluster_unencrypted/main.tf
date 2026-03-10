resource "aws_redshift_cluster" "unencrypted_cluster" {
  cluster_identifier = "insecure-cluster"
  database_name      = "mydb"
  master_username    = "admin"
  master_password    = "Password123!"
  node_type          = "dc2.large"
  cluster_type       = "single-node"

  # CRITICAL FLAW: Encryption is set to false
  encrypted          = false
}