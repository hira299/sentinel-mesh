resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}

# CRITICAL FLAW: Modifying the Default Security Group to allow traffic. 
# Best practice is to leave the default SG empty and create specific SGs for resources.
resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.main.id

  ingress {
    protocol  = -1
    self      = true
    from_port = 0
    to_port   = 0
  }
}