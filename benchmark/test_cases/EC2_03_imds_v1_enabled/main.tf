resource "aws_instance" "imds_v1" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"

  metadata_options {
    # CRITICAL FLAW: HTTP tokens 'optional' means IMDSv1 is still enabled
    http_tokens = "optional"
  }
}