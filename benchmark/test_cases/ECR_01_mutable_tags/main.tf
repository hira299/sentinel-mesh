resource "aws_ecr_repository" "insecure_repo" {
  name                 = "vulnerable-app"
  
  # CRITICAL FLAW: Tags are mutable; an attacker could overwrite a safe image with a malicious one
  image_tag_mutability = "MUTABLE"
}