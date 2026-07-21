# wild_lambda_func.tf
# Source pattern: adapted from a serverless API backend open-source project.
# Misconfigurations: no VPC, environment vars with secrets in plaintext,
# no reserved concurrency, no dead letter queue, overly long timeout,
# no code signing, X-Ray tracing disabled, insecure function URL with no auth.

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

resource "aws_iam_role" "lambda_role" {
  name = "api-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

# MISCONFIGURATION: grants full administrator access to Lambda execution role.
resource "aws_iam_role_policy_attachment" "lambda_admin" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_s3_bucket" "lambda_artifacts" {
  bucket = "corp-lambda-artifacts-prod"
}

resource "aws_s3_object" "api_handler_zip" {
  bucket = aws_s3_bucket.lambda_artifacts.id
  key    = "api-handler/v1.2.3/handler.zip"
  source = "dist/handler.zip"
  etag   = filemd5("dist/handler.zip")
}

resource "aws_lambda_function" "api_handler" {
  function_name = "api-handler"
  role          = aws_iam_role.lambda_role.arn
  handler       = "index.handler"
  runtime       = "nodejs18.x"
  timeout       = 900          # MISCONFIGURATION: maximum Lambda timeout; resource waste risk.
  memory_size   = 1024

  s3_bucket = aws_s3_bucket.lambda_artifacts.id
  s3_key    = aws_s3_object.api_handler_zip.key

  # MISCONFIGURATION: sensitive values passed as plaintext environment variables;
  # no KMS CMK specified for environment variable encryption.
  environment {
    variables = {
      DB_PASSWORD    = "production-secret-abc123"  # MISCONFIGURATION: hardcoded secret.
      API_SECRET_KEY = "sk-prod-xxxxxxxxxxxxxxxx"  # MISCONFIGURATION: hardcoded API key.
      STRIPE_KEY     = "sk_live_xxxxxxxxxxxxxxxxxx"
      ENV            = "production"
    }
  }

  # MISCONFIGURATION: tracing_config mode = PassThrough; X-Ray tracing disabled.
  tracing_config {
    mode = "PassThrough"
  }

  # MISCONFIGURATION: no vpc_config; function runs outside VPC with direct internet access.

  # MISCONFIGURATION: no dead_letter_config; failed async invocations silently discarded.

  # MISCONFIGURATION: reserved_concurrent_executions not set; function can consume all
  # regional concurrency, causing account-wide throttling.

  # MISCONFIGURATION: no code_signing_config_arn; arbitrary code can be deployed.

  tags = {
    Environment = "production"
    Team        = "backend"
  }
}

# MISCONFIGURATION: function URL with auth_type = NONE; publicly invocable without
# any authentication or authorization check.
resource "aws_lambda_function_url" "api_handler_url" {
  function_name      = aws_lambda_function.api_handler.function_name
  authorization_type = "NONE"  # MISCONFIGURATION: no auth on public function URL.

  cors {
    allow_credentials = true
    allow_origins     = ["*"]  # MISCONFIGURATION: CORS wildcard origin.
    allow_methods     = ["*"]
    allow_headers     = ["*"]
    max_age           = 86400
  }
}

# MISCONFIGURATION: EventBridge rule triggers Lambda with no resource-based policy
# restriction; over-broad invocation surface.
resource "aws_cloudwatch_event_rule" "hourly_trigger" {
  name                = "hourly-api-trigger"
  schedule_expression = "rate(1 hour)"
}

resource "aws_cloudwatch_event_target" "lambda_target" {
  rule      = aws_cloudwatch_event_rule.hourly_trigger.name
  target_id = "ApiHandlerLambda"
  arn       = aws_lambda_function.api_handler.arn
}

output "function_url" {
  value = aws_lambda_function_url.api_handler_url.function_url
}
