resource "aws_lambda_function" "long_running_lambda" {
  function_name = "potential-dos-lambda"
  role          = "arn:aws:iam::123456789012:role/lambda-role"
  handler       = "index.handler"
  runtime       = "nodejs18.x"

  # CRITICAL FLAW: Timeout set to maximum (15 mins) without clear need. 
  # Increases risk of runaway costs or resource exhaustion if the code loops.
  timeout = 900 
}