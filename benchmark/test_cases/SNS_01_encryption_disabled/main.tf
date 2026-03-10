resource "aws_sns_topic" "unencrypted_topic" {
  name = "unencrypted-notifications"
  # CRITICAL FLAW: kms_master_key_id is missing, meaning messages are not encrypted at rest
}