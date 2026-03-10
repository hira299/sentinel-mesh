resource "aws_glue_data_catalog_encryption_settings" "disabled" {
  # CRITICAL FLAW: Encryption for the Glue Data Catalog is explicitly disabled or missing
  encryption_at_rest {
    catalog_encryption_mode = "DISABLED"
  }
}