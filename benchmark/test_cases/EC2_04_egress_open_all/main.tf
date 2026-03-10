resource "aws_security_group" "open_egress" {
  name        = "open-egress-sg"
  description = "Dangerous egress"

  egress {
    # CRITICAL FLAW: Allows all traffic to all destinations
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}