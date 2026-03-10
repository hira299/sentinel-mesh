resource "aws_lb" "vulnerable_alb" {
  name               = "vulnerable-alb"
  load_balancer_type = "application"
  subnets            = ["subnet-12345", "subnet-67890"]

  # CRITICAL FLAW: Setting desync_mitigation_mode to 'monitor' or 'defensive' (instead of 'strictest') 
  # can leave the LB vulnerable to HTTP Desync/Request Smuggling attacks.
  desync_mitigation_mode = "monitor"
}