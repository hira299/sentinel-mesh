resource "aws_guardduty_detector" "disabled_detector" {
  # CRITICAL FLAW: GuardDuty detector is created but explicitly disabled,
  # leaving the account without intelligent threat detection.
  enable = false
}