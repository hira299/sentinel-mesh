resource "aws_db_instance" "unprotected_db" {
  allocated_storage    = 20
  engine               = "mysql"
  instance_class       = "db.t3.micro"
  db_name              = "mydb"
  
  # CRITICAL FLAW: Deletion protection is false, allowing accidental or malicious deletion
  deletion_protection  = false
  skip_final_snapshot  = true
}