resource "aws_batch_job_definition" "privileged_job" {
  name = "privileged-batch-job"
  type = "container"

  container_properties = jsonencode({
    command = ["echo", "hello"]
    image   = "busybox"
    resourceRequirements = [
      { type = "VCPU", value = "0.25" },
      { type = "MEMORY", value = "512" }
    ]
    # CRITICAL FLAW: Batch job runs in privileged mode, granting it 
    # dangerous root-level access to the underlying host.
    privileged = true
  })
}