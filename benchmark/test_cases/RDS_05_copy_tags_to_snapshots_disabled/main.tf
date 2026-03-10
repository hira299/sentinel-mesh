resource "aws_db_instance" "no_tag_copy_db" {
  allocated_storage    = 20
  engine               = "mysql"
  instance_class       = "db.t3.micro"
  
  # CRITICAL FLAW: Security metadata (tags) are not copied to snapshots. 
  # This leads to loss of data classification/ownership info on backups.
  copy_tags_to_snapshot = false
}