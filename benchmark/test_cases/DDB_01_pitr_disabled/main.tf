resource "aws_dynamodb_table" "insecure_table" {
  name           = "GameScores"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "UserId"

  attribute {
    name = "UserId"
    type = "S"
  }

  # CRITICAL FLAW: Point-in-time recovery is disabled by default/omission
  point_in_time_recovery {
    enabled = false
  }
}