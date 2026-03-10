resource "aws_launch_configuration" "insecure_config" {
  name          = "web_config"
  image_id      = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"

  # CRITICAL FLAW: Automatically assigns a public IP to every instance in the ASG
  associate_public_ip_address = true
}