resource "aws_memorydb_cluster" "insecure_memorydb" {
  name       = "insecure-memorydb"
  node_type  = "db.t4g.small"
  acl_name   = "open-access"
  
  # CRITICAL FLAW: TLS is disabled for data in transit
  tls_enabled = false
}