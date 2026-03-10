resource "aws_opensearch_domain" "insecure_domain" {
  domain_name    = "logs-domain"
  engine_version = "OpenSearch_1.1"

  cluster_config {
    instance_type = "t3.small.search"
  }

  # CRITICAL FLAW: Node-to-node encryption is explicitly false
  node_to_node_encryption {
    enabled = false
  }
}