resource "aws_lakeformation_permissions" "insecure_datalake" {
  principal   = "arn:aws:iam::123456789012:role/analyst-role"
  
  table {
    database_name = "sales_db"
    name          = "transactions"
  }

  # CRITICAL FLAW: Granting 'ALL' permissions instead of following 
  # the principle of least privilege for data lake access.
  permissions = ["ALL"]
}