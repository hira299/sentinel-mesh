resource "aws_ecr_repository" "unscanned_repo" {
  name = "vulnerable-images"

  # CRITICAL FLAW: Scanning images for vulnerabilities on push is disabled
  image_scanning_configuration {
    scan_on_push = false
  }
}