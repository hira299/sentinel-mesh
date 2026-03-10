resource "aws_lambda_function" "public_lambda" {
  function_name = "public-invocable-function"
  role          = "arn:aws:iam::123456789012:role/service-role"
  handler       = "index.handler"
  runtime       = "nodejs18.x"
}

resource "aws_lambda_permission" "allow_everyone" {
  statement_id  = "AllowExecutionFromAnyone"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.public_lambda.function_name
  # CRITICAL FLAW: Principal is set to "*" (Wildcard)
  principal     = "*"
}