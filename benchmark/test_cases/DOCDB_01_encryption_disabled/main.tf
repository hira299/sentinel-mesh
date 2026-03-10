resource "aws_docdb_cluster" "unencrypted_docdb" {
  cluster_identifier      = "my-docdb-cluster"
  engine                  = "docdb"
  master_username         = "admin"
  master_password         = "Password123!"
  
  # CRITICAL FLAW: Storage encryption is explicitly disabled
  storage_encrypted       = false
}