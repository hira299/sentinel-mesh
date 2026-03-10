resource "aws_ami" "unencrypted_image" {
  name                = "unencrypted-ami"
  virtualization_type = "hvm"
  root_device_name    = "/dev/xvda"

  ebs_block_device {
    device_name = "/dev/xvda"
    snapshot_id = "snap-1234567890abcdef0"
    # CRITICAL FLAW: The AMI root volume is not encrypted. 
    # Any instance launched from this image will be unencrypted by default.
    encrypted   = false
  }
}