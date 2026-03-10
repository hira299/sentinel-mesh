resource "aws_lb" "unlogged_alb" {
  name               = "unlogged-alb"
  internal           = false
  load_balancer_type = "application"
  subnets            = ["subnet-12345", "subnet-67890"]

  # CRITICAL FLAW: access_logs block is missing. 
  # Request patterns and potential attacks cannot be audited.
}