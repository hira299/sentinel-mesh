resource "aws_instance" "standard_monitoring" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"

  # CRITICAL FLAW: Detailed monitoring (1-minute intervals) is disabled. 
  # This makes it harder to respond quickly to performance anomalies or brute-force attacks.
  monitoring = false
}