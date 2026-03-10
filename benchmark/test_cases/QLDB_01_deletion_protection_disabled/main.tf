resource "aws_qldb_ledger" "unprotected_ledger" {
  name             = "unprotected-ledger"
  permissions_mode = "STANDARD"
  # CRITICAL FLAW: Deletion protection is disabled on a ledger database, 
  # which is meant to be an immutable, cryptographically verifiable record.
  deletion_protection = false
}