resource "aws_mq_broker" "public_broker" {
  broker_name        = "public-mq"
  engine_type        = "ActiveMQ"
  engine_version     = "5.15.0"
  host_instance_type = "mq.t2.micro"

  # CRITICAL FLAW: Broker is accessible from the public internet
  publicly_accessible = true

  user {
    username = "admin"
    password = "Password123456!"
  }
}