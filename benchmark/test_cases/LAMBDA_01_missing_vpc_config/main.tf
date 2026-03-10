resource "aws_lambda_function" "insecure_lambda" {
  function_name = "insecure-function"
  role          = "arn:aws:iam::123456789012:role/dummy"
  handler       = "index.handler"
  runtime       = "nodejs18.x"
  
  # CRITICAL FLAW: Missing vpc_config block
}