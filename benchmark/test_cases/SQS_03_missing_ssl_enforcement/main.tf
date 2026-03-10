resource "aws_sqs_queue" "insecure_transport" {
  name = "insecure-transport-queue"
}

resource "aws_sqs_queue_policy" "no_ssl_check" {
  queue_url = aws_sqs_queue.insecure_transport.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sqs:*"
      Effect    = "Allow"
      Principal = "*"
      Resource  = aws_sqs_queue.insecure_transport.arn
      # CRITICAL FLAW: Missing a 'Deny' statement for 'aws:SecureTransport': 'false'.
      # This allows data to be sent to the queue over unencrypted HTTP.
    }]
  })
}