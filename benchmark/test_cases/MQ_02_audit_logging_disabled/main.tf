resource "aws_mq_broker" "unlogged_mq" {
  broker_name        = "unlogged-broker"
  engine_type        = "ActiveMQ"
  engine_version     = "5.15.0"
  host_instance_type = "mq.t2.micro"

  # CRITICAL FLAW: Audit logging is not explicitly enabled. 
  # Management actions on the broker will not be recorded in CloudWatch.
  logs {
    audit   = false
    general = true
  }
}