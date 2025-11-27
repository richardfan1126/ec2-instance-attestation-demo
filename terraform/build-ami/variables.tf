variable "region" {
  description = "AWS region for infrastructure"
  type        = string
}

variable "allowed_ssh_cidr" {
  description = "CIDR block allowed to SSH to AMI build instance"
  type        = string
}

variable "instance_type" {
  description = "Instance type for AMI build instance"
  type        = string
  default     = "c5.9xlarge"
}
