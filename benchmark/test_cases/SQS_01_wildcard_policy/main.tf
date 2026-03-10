resource "aws_sqs_queue" "insecure_queue" {
  name = "insecure-queue"
}

resource "aws_sqs_queue_policy" "wildcard_policy" {
  queue_url = aws_sqs_queue.insecure_queue.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sqs:*"
      Effect    = "Allow"
      # CRITICAL FLAW: Wildcard principal allows anyone to access the queue
      Principal = "*"
      Resource  = aws_sqs_queue.insecure_queue.arn
    }]
  })
}
