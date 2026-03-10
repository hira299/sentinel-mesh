resource "aws_ecs_task_definition" "insecure_task" {
  family                = "service"
  container_definitions = jsonencode([
    {
      name      = "first"
      image     = "service-first"
      cpu       = 10
      memory    = 512
      essential = true
      # CRITICAL FLAW: Privileged mode gives the container root access to the host
      privileged = true
      portMappings = [
        {
          containerPort = 80
          hostPort      = 80
        }
      ]
    }
  ])
}