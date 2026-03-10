resource "aws_msk_cluster" "insecure_msk" {
  cluster_name           = "insecure-msk"
  kafka_version          = "2.8.1"
  number_of_broker_nodes = 3

  encryption_info {
    encryption_in_transit {
      # CRITICAL FLAW: Allows plaintext communication between client and broker
      client_broker = "PLAINTEXT"
      in_cluster    = true
    }
  }

  broker_node_group_info {
    instance_type = "kafka.m5.large"
    client_subnets = ["subnet-12345", "subnet-67890", "subnet-abcde"]
    security_groups = ["sg-12345"]
  }
}