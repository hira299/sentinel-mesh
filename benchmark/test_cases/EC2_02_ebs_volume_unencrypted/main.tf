resource "aws_instance" "unencrypted_ebs" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"

  root_block_device {
    # CRITICAL FLAW: encryption is explicitly set to false
    encrypted = false
  }
}