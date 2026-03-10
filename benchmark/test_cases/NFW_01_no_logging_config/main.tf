resource "aws_networkfirewall_firewall" "unlogged_firewall" {
  name                = "unlogged-nfw"
  firewall_policy_arn = "arn:aws:network-firewall:us-east-1:123456789012:firewall-policy/test"
  vpc_id              = "vpc-12345"
  
  subnet_mapping {
    subnet_id = "subnet-12345"
  }
  # CRITICAL FLAW: No aws_networkfirewall_logging_configuration is attached.
  # Traffic passing through the firewall is not being audited or recorded.
}