resource "aws_iam_user" "no_mfa_user" {
  name = "human-operator"
}

# CRITICAL FLAW: This is an architectural vulnerability. 
# While Terraform can't "force" a user to setup a device, 
# the lack of an IAM Policy requiring MFA for this user's actions is the bug.