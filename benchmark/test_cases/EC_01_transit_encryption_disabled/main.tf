resource "aws_elasticache_replication_group" "insecure_redis" {
  replication_group_id          = "tf-redis-cluster"
  replication_group_description = "Redis cluster"
  node_type                     = "cache.t3.micro"
  port                          = 6379

  # CRITICAL FLAW: Data in transit is not encrypted
  transit_encryption_enabled    = false
}