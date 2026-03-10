resource "aws_ssm_document" "example" {
  name          = "example_document"
  document_type = "Command"
  content       = jsonencode({
    schemaVersion = "2.2"
    mainSteps = [{
      action = "aws:runShellScript"
      name   = "runShellScript"
      inputs = { runCommand = ["echo hello"] }
    }]
  })
}

# CRITICAL FLAW: Sharing a Systems Manager document with 'all' (Public). 
# This could leak proprietary automation logic or scripts to the world.
resource "aws_ssm_document_permission" "public_share" {
  name       = aws_ssm_document.example.name
  permission_type = "Share"
  account_ids     = ["all"]
}