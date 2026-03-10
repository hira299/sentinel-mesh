resource "aws_iot_policy" "excessive_iot_policy" {
  name = "excessive-iot-policy"

  # CRITICAL FLAW: IoT policy allows any action on any resource. 
  # A single compromised device could control the entire IoT fleet.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = "*"
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}