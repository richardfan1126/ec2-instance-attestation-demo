output "instance_id" {
  description = "AMI build instance ID"
  value       = aws_instance.this.id
}

output "instance_public_ip" {
  description = "AMI build instance public IP"
  value       = aws_instance.this.public_ip
}

output "ssh_private_key" {
  description = "SSH private key for AMI build instance"
  value       = tls_private_key.this.private_key_pem
  sensitive   = true
}

output "vpc_id" {
  description = "VPC ID"
  value       = aws_vpc.this.id
}

output "security_group_id" {
  description = "Security group ID for AMI build instance"
  value       = aws_security_group.this.id
}
