resource "aws_docdb_cluster_instance" "public_instance" {
  cluster_identifier = "my-cluster"
  instance_class     = "db.r5.large"
  # CRITICAL FLAW: DocumentDB instance is exposed to the public internet
  publicly_accessible = true
}