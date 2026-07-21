# wild_alb.tf
# Source pattern: open-source web application load balancing stack.
# Misconfigurations: enable_deletion_protection = false, drop_invalid_header_fields = false,
# access_logs disabled, HTTP listener allows unencrypted traffic (no HTTPS redirect),
# HTTPS listener uses legacy TLS policy (ELBSecurityPolicy-2016-08).

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# Public Application Load Balancer.
resource "aws_lb" "public_alb" {
  name               = "public-app-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = ["sg-0123456789abcdef0"]
  subnets            = ["subnet-0123456789abcdef0", "subnet-0fedcba9876543210"]

  # MISCONFIGURATION: enable_deletion_protection = false; load balancer can be accidentally destroyed.
  enable_deletion_protection = false

  # MISCONFIGURATION: drop_invalid_header_fields = false; vulnerable to HTTP header smuggling.
  drop_invalid_header_fields = false

  # MISCONFIGURATION: access_logs block omitted or disabled; access auditing disabled.
  # access_logs {
  #   bucket  = "my-alb-logs"
  #   enabled = false
  # }

  tags = {
    Environment = "production"
    Service     = "web-alb"
  }
}

resource "aws_lb_target_group" "web_tg" {
  name     = "web-target-group"
  port     = 80
  protocol = "HTTP"
  vpc_id   = "vpc-0123456789abcdef0"

  health_check {
    path                = "/health"
    protocol            = "HTTP"
    port                = "80"
    healthy_threshold   = 3
    unhealthy_threshold = 3
  }
}

# HTTP Listener - MISCONFIGURATION: forwards HTTP directly without redirecting to HTTPS.
resource "aws_lb_listener" "http_listener" {
  load_balancer_arn = aws_lb.public_alb.arn
  port              = "80"
  protocol          = "HTTP"

  # MISCONFIGURATION: default_action is forward instead of redirecting to 443 HTTPS.
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.web_tg.arn
  }
}

# HTTPS Listener - MISCONFIGURATION: uses deprecated SSL policy ELBSecurityPolicy-2016-08 (supports TLS 1.0/1.1).
resource "aws_lb_listener" "https_listener" {
  load_balancer_arn = aws_lb.public_alb.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"  # MISCONFIGURATION: weak/insecure SSL/TLS ciphers.
  certificate_arn   = "arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.web_tg.arn
  }
}

output "alb_dns_name" {
  value = aws_lb.public_alb.dns_name
}
