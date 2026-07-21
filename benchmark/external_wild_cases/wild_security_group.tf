# wild_security_group.tf
# Source pattern: bootstrapped from a legacy DevOps migration project.
# Misconfigurations: unrestricted SSH, RDP, all-port egress, management port exposure,
# no description on rules, overly broad CIDR ranges.

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-west-2"
}

# Web-tier security group.
# MISCONFIGURATION: allows SSH (22) and RDP (3389) from the entire internet.
resource "aws_security_group" "web_tier" {
  name        = "web-tier-sg"
  description = "Web tier security group"
  vpc_id      = "vpc-0cafebabe"

  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # MISCONFIGURATION: SSH open to entire internet; allows brute-force and exploitation.
  ingress {
    description = "SSH open"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # MISCONFIGURATION: RDP exposed publicly; Windows management surface available globally.
  ingress {
    description = "RDP open"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # MISCONFIGURATION: unrestricted all-protocol egress; no egress filtering.
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "web-tier-sg"
    Tier = "web"
  }
}

# Application-tier security group.
resource "aws_security_group" "app_tier" {
  name        = "app-tier-sg"
  description = "Application tier security group"
  vpc_id      = "vpc-0cafebabe"

  # MISCONFIGURATION: accepts all traffic on all ports from any source; no port restriction.
  ingress {
    description = "All traffic"
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # MISCONFIGURATION: IPv6 also unrestricted.
  ingress {
    from_port        = 0
    to_port          = 65535
    protocol         = "tcp"
    ipv6_cidr_blocks = ["::/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "app-tier-sg"
    Tier = "application"
  }
}

# Database security group.
resource "aws_security_group" "db_tier" {
  name        = "db-tier-sg"
  description = "Database tier security group"
  vpc_id      = "vpc-0cafebabe"

  # MISCONFIGURATION: MySQL/Aurora port open to entire VPC CIDR AND public internet.
  ingress {
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0", "10.0.0.0/8"]
  }

  # MISCONFIGURATION: PostgreSQL also world-accessible on same SG.
  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "db-tier-sg"
    Tier = "database"
  }
}

# MISCONFIGURATION: standalone rule added to web-tier sg to allow ICMP (ping) globally.
resource "aws_security_group_rule" "web_icmp" {
  type              = "ingress"
  from_port         = -1
  to_port           = -1
  protocol          = "icmp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.web_tier.id
  description       = "Allow ICMP from world"
}
