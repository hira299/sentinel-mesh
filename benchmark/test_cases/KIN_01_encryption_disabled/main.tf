resource "aws_kinesis_stream" "unencrypted_stream" {
  name             = "unencrypted-data-stream"
  shard_count      = 1
  # CRITICAL FLAW: encryption_type is set to NONE
  encryption_type = "NONE"
}