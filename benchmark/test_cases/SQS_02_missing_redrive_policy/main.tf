resource "aws_sqs_queue" "no_dlq_queue" {
  name = "queue-without-dlq"
  # CRITICAL FLAW: No redrive_policy (Dead Letter Queue) defined. 
}