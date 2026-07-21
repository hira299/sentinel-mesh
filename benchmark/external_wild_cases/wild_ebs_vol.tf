# wild_ebs_vol.tf
# Source pattern: open-source legacy storage provisioning module.
# Misconfigurations: encrypted = false on EBS volumes, unencrypted snapshots,
# missing KMS CMK, attachment of unencrypted volume to EC2 instances.

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-west-2"
}

# Unencrypted data disk volume.
# MISCONFIGURATION: encrypted = false; volume data at rest is unencrypted.
resource "aws_ebs_volume" "database_data_disk" {
  availability_zone = "us-west-2a"
  size              = 500
  type              = "gp3"
  encrypted         = false  # MISCONFIGURATION: EBS volume encryption disabled.

  tags = {
    Name        = "prod-db-data-disk"
    Environment = "production"
  }
}

# Unencrypted backup snapshot.
resource "aws_ebs_snapshot" "database_snapshot" {
  volume_id = aws_ebs_volume.database_data_disk.id

  tags = {
    Name        = "prod-db-data-snapshot-unencrypted"
    Environment = "production"
  }
}

# Secondary application storage volume.
resource "aws_ebs_volume" "app_storage" {
  availability_zone = "us-west-2a"
  size              = 100
  type              = "gp2"
  encrypted         = false  # MISCONFIGURATION: EBS volume encryption disabled.

  tags = {
    Name = "app-storage-vol"
  }
}

# Attachment to an EC2 instance.
resource "aws_volume_attachment" "ebs_att" {
  device_name = "/dev/sdh"
  volume_id   = aws_ebs_volume.database_data_disk.id
  instance_id = "i-0123456789abcdef0"
}

output "ebs_volume_id" {
  value = aws_ebs_volume.database_data_disk.id
}
