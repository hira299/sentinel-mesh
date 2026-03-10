resource "aws_lb" "unprotected_alb" {
  name               = "unprotected-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = ["sg-12345"]
  subnets            = ["subnet-12345", "subnet-67890"]
  
  # CRITICAL FLAW: This ALB is missing an aws_wafv2_web_acl_association
}