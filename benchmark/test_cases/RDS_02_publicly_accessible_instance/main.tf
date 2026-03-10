resource "aws_db_instance" "public_db" {
  allocated_storage    = 10
  engine               = "postgres"
  instance_class       = "db.t3.micro"
  username             = "dbadmin"
  password             = "MustBeSecret123!"
  
  # CRITICAL FLAW: Instance is accessible from the internet
  publicly_accessible  = true
}