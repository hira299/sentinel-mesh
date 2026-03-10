resource "aws_lb_listener" "insecure_listener" {
  load_balancer_arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-load-balancer/50dc6c495c0c9188"
  port              = "443"
  protocol          = "HTTPS"
  
  # CRITICAL FLAW: Using an old, insecure security policy
  ssl_policy        = "ELBSecurityPolicy-TLS-1-0-2015-04"
  certificate_arn   = "arn:aws:iam::123456789012:server-certificate/test_cert_rb06"

  default_action {
    type             = "forward"
    target_group_arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/my-targets/73e2d6bc24d8a067"
  }
}