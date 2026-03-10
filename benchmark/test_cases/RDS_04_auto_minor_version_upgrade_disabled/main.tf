resource "aws_db_instance" "outdated_db" {
  allocated_storage    = 10
  engine               = "postgres"
  instance_class       = "db.t3.micro"
  
  # CRITICAL FLAW: Auto minor version upgrade is disabled, 
  # preventing automatic patching of security vulnerabilities.
  auto_minor_version_upgrade = false
}