# wild_sqs_queue.tf
# Source pattern: adapted from open-source event-driven microservice infrastructure.
# Misconfigurations: SSE disabled, no DLQ configured, overly permissive resource
# policy allowing all actions from all principals, no VPC endpoint, message
# retention period at minimum, visibility timeout mismatch.

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# Primary order-processing queue.
# MISCONFIGURATION: kms_master_key_id absent; SSE-SQS (not SSE-KMS) used by default,
# providing no CMK-level key rotation control or cross-account audit trail.
resource "aws_sqs_queue" "order_processing" {
  name                       = "order-processing-queue"
  delay_seconds              = 0
  max_message_size           = 262144
  message_retention_seconds  = 60      # MISCONFIGURATION: 60 seconds; messages silently
                                       # discarded before consumers can process them.
  receive_wait_time_seconds  = 0       # MISCONFIGURATION: short-polling wastes API quota.
  visibility_timeout_seconds = 30

  # MISCONFIGURATION: no redrive_policy; failed messages accumulate without DLQ capture.

  tags = {
    Environment = "production"
    Service     = "order-processing"
  }
}

# MISCONFIGURATION: resource policy grants all SQS actions to all AWS principals.
resource "aws_sqs_queue_policy" "order_processing_policy" {
  queue_url = aws_sqs_queue.order_processing.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowAll"
        Effect    = "Allow"
        Principal = "*"         # MISCONFIGURATION: wildcard principal; any AWS entity.
        Action    = "SQS:*"    # MISCONFIGURATION: all SQS actions including DeleteQueue.
        Resource  = aws_sqs_queue.order_processing.arn
      }
    ]
  })
}

# Notification dispatch queue.
resource "aws_sqs_queue" "notification_dispatch" {
  name                      = "notification-dispatch-queue"
  message_retention_seconds = 86400   # 1 day retention.
  visibility_timeout_seconds = 300

  # MISCONFIGURATION: kms_master_key_id not set; no encryption at rest beyond default SSE-SQS.
}

# MISCONFIGURATION: Dead letter queue itself has no encryption or retention policy guardrail.
resource "aws_sqs_queue" "notification_dlq" {
  name                      = "notification-dispatch-dlq"
  message_retention_seconds = 604800  # 7 days.
}

resource "aws_sqs_queue_redrive_policy" "notification_dispatch_redrive" {
  queue_url = aws_sqs_queue.notification_dispatch.id

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.notification_dlq.arn
    maxReceiveCount     = 5
  })
}

# FIFO queue for inventory updates.
# MISCONFIGURATION: content_based_deduplication used without understanding implications;
# malicious duplicate suppression possible via content manipulation.
resource "aws_sqs_queue" "inventory_updates_fifo" {
  name                        = "inventory-updates.fifo"
  fifo_queue                  = true
  content_based_deduplication = true  # MISCONFIGURATION: dedup based on message body hash.
  message_retention_seconds   = 3600  # MISCONFIGURATION: 1 hour; insufficient for batch jobs.

  # MISCONFIGURATION: no kms_master_key_id on FIFO queue.
}

# SNS topic triggering all three queues.
resource "aws_sns_topic" "events_fanout" {
  name = "platform-events-fanout"
  # MISCONFIGURATION: no kms_master_key_id; SNS messages unencrypted at rest.
}

resource "aws_sns_topic_subscription" "order_sub" {
  topic_arn = aws_sns_topic.events_fanout.arn
  protocol  = "sqs"
  endpoint  = aws_sqs_queue.order_processing.arn

  # MISCONFIGURATION: raw_message_delivery = false; JSON envelope wrapping may confuse
  # consumers but the default is acceptable; included for completeness.
}

resource "aws_sns_topic_subscription" "notification_sub" {
  topic_arn = aws_sns_topic.events_fanout.arn
  protocol  = "sqs"
  endpoint  = aws_sqs_queue.notification_dispatch.arn
}

output "order_queue_url" {
  value = aws_sqs_queue.order_processing.url
}

output "fanout_topic_arn" {
  value = aws_sns_topic.events_fanout.arn
}
