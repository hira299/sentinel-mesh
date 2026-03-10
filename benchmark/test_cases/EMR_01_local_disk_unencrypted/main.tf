resource "aws_emr_security_configuration" "insecure_emr" {
  name = "insecure-emr-config"

  configuration = jsonencode({
    EncryptionConfiguration = {
      AtRestEncryptionConfiguration = {
        # CRITICAL FLAW: Local disk encryption is disabled, exposing data in temporary EMR storage
        LocalDiskEncryptionConfiguration = {
          EncryptionKeyProviderType = "KMS"
          EnableLocalStorageEncryption = false
        }
      }
    }
  })
}