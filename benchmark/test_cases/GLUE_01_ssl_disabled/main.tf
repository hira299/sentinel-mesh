resource "aws_glue_connection" "insecure_connection" {
  name = "insecure-jdbc-connection"

  connection_properties = {
    JDBC_CONNECTION_URL = "jdbc:mysql://example.com:3306/db"
    PASSWORD            = "example-password"
    USERNAME            = "example-username"
    # CRITICAL FLAW: ENFORCE_SSL is set to false
    ENFORCE_SSL         = "false"
  }
}