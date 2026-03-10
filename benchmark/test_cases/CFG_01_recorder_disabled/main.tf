resource "aws_config_configuration_recorder" "disabled_recorder" {
  name     = "default"
  role_arn = "arn:aws:iam::123456789012:role/config-role"
}

resource "aws_config_configuration_recorder_status" "is_off" {
  name       = aws_config_configuration_recorder.disabled_recorder.name
  # CRITICAL FLAW: Recording is explicitly set to false
  is_enabled = false
}