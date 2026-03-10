resource "aws_vpc" "unmonitored_vpc" {
  cidr_block = "10.0.0.0/16"
  # CRITICAL FLAW: A VPC is created but no aws_flow_log resource is associated to it, 
  # leaving the network with no traffic audit trail.
}