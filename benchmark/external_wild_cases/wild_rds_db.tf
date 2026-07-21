# wild_rds_db.tf
# Source pattern: bootstrapped from open-source SaaS application Terraform modules.
# Misconfigurations: publicly accessible, storage not encrypted, no deletion protection,
# no IAM authentication, no enhanced monitoring, short backup retention.

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "eu-west-1"
}

resource "aws_db_subnet_group" "app_db_subnet" {
  name       = "app-db-subnet-group"
  subnet_ids = ["subnet-0abc1234", "subnet-0def5678"]

  tags = {
    Name = "app-db-subnet-group"
  }
}

# MISCONFIGURATION: security group allows inbound 5432 from 0.0.0.0/0.
resource "aws_security_group" "rds_sg" {
  name        = "rds-open-sg"
  description = "RDS security group"
  vpc_id      = "vpc-0deadbeef"

  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # MISCONFIGURATION: world-accessible database port.
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_parameter_group" "app_pg14" {
  name   = "app-pg14-params"
  family = "postgres14"

  parameter {
    name  = "log_connections"
    value = "0"  # MISCONFIGURATION: connection logging disabled; no audit trail.
  }

  parameter {
    name  = "log_disconnections"
    value = "0"
  }

  parameter {
    name  = "rds.force_ssl"
    value = "0"  # MISCONFIGURATION: TLS not enforced; allows plaintext connections.
  }
}

resource "aws_db_instance" "app_primary" {
  identifier        = "app-primary-db"
  engine            = "postgres"
  engine_version    = "14.10"
  instance_class    = "db.t3.medium"
  allocated_storage = 100
  storage_type      = "gp3"

  db_name  = "appdb"
  username = "dbadmin"
  password = "SuperSecret1234!"  # MISCONFIGURATION: hardcoded credential in source.

  db_subnet_group_name   = aws_db_subnet_group.app_db_subnet.name
  vpc_security_group_ids = [aws_security_group.rds_sg.id]
  parameter_group_name   = aws_db_parameter_group.app_pg14.name

  # MISCONFIGURATION: storage_encrypted = false; data at rest is unprotected.
  storage_encrypted = false

  # MISCONFIGURATION: publicly_accessible = true; database endpoint resolvable from internet.
  publicly_accessible = true

  # MISCONFIGURATION: deletion_protection = false; instance can be destroyed accidentally.
  deletion_protection = false

  # MISCONFIGURATION: backup_retention_period = 1; only 1 day of PITR coverage.
  backup_retention_period = 1

  # MISCONFIGURATION: skip_final_snapshot = true; no snapshot on deletion.
  skip_final_snapshot = true

  # MISCONFIGURATION: iam_database_authentication_enabled = false; password-only auth.
  iam_database_authentication_enabled = false

  # MISCONFIGURATION: enabled_cloudwatch_logs_exports absent; no log forwarding to CWL.
  # enhanced monitoring omitted (monitoring_interval defaults to 0).

  multi_az               = false  # MISCONFIGURATION: single-AZ; no automatic failover.
  auto_minor_version_upgrade = false

  tags = {
    Environment = "production"
    Terraform   = "true"
  }
}

resource "aws_db_instance" "app_replica" {
  identifier          = "app-replica-db"
  instance_class      = "db.t3.medium"
  replicate_source_db = aws_db_instance.app_primary.identifier

  # MISCONFIGURATION: read replica also publicly accessible.
  publicly_accessible = true
  storage_encrypted   = false
  skip_final_snapshot = true

  tags = {
    Environment = "production"
    Role        = "read-replica"
  }
}

output "rds_endpoint" {
  value     = aws_db_instance.app_primary.endpoint
  sensitive = false  # MISCONFIGURATION: endpoint exposed in output without sensitive flag.
}
