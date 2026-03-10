resource "aws_redshift_cluster" "public_redshift" {
  cluster_identifier = "public-cluster"
  node_type          = "dc2.large"
  master_username    = "admin"
  master_password    = "Password123!"

  # CRITICAL FLAW: Cluster is accessible from the public internet
  publicly_accessible = true
}