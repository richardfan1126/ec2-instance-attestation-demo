output "vpc_id" {
  description = "ID of the VPC"
  value       = aws_vpc.main.id
}

output "subnet_id" {
  description = "ID of the public subnet"
  value       = aws_subnet.public.id
}

output "security_group_id" {
  description = "ID of the security group"
  value       = aws_security_group.attestation_api.id
}

output "instance_id" {
  description = "ID of the EC2 instance"
  value       = aws_instance.target.id
}

output "instance_public_ip" {
  description = "Public IP address of the instance"
  value       = aws_instance.target.public_ip
}

output "attestation_api_url" {
  description = "URL of the attestation API endpoint"
  value       = "http://${aws_instance.target.public_ip}:8080"
}
