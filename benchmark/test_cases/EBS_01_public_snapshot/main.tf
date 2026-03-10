resource "aws_ebs_volume" "example" {
  availability_zone = "us-east-1a"
  size              = 40
}

resource "aws_ebs_snapshot" "example_snapshot" {
  volume_id = aws_ebs_volume.example.id
}

# CRITICAL FLAW: Sharing an EBS snapshot with the 'all' account group (Public)
resource "aws_snapshot_create_volume_permission" "public_share" {
  snapshot_id = aws_ebs_snapshot.example_snapshot.id
  group       = "all"
}