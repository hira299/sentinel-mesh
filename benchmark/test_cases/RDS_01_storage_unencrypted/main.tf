resource "aws_db_instance" "insecure_db" {
  allocated_storage    = 20
  engine               = "mysql"
  instance_class       = "db.t3.micro"
  username             = "admin"
  password             = "password123"
  
  # CRITICAL FLAW: Storage is not encrypted
  storage_encrypted    = false 
}