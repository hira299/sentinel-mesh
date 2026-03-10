resource "aws_backup_vault" "unencrypted_vault" {
  name = "insecure-backup-vault"
  # CRITICAL FLAW: kms_key_arn is missing, meaning backups in this vault are not encrypted
}