terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region = var.region
}

# Data source for availability zones
data "aws_availability_zones" "available" {
  state = "available"
}

# Data source for Amazon Linux 2023 AMI
data "aws_ami" "amazon_linux_2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-kernel-*"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# VPC
resource "aws_vpc" "this" {
  cidr_block           = "10.2.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "build-attestable-ami-vpc"
  }
}

# Public subnet
resource "aws_subnet" "this" {
  vpc_id                  = aws_vpc.this.id
  cidr_block              = "10.2.1.0/24"
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true

  tags = {
    Name = "build-attestable-ami-subnet"
  }
}

# Internet Gateway
resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id

  tags = {
    Name = "build-attestable-ami-igw"
  }
}

# Route table for internet access
resource "aws_route_table" "this" {
  vpc_id = aws_vpc.this.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this.id
  }

  tags = {
    Name = "build-attestable-ami-rt"
  }
}

# Associate route table with subnet
resource "aws_route_table_association" "this" {
  subnet_id      = aws_subnet.this.id
  route_table_id = aws_route_table.this.id
}

# Security group for AMI build instance
resource "aws_security_group" "this" {
  name        = "build-attestable-ami-sg"
  description = "Security group for AMI build instance"
  vpc_id      = aws_vpc.this.id

  ingress {
    description = "SSH access from allowed CIDR"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ssh_cidr]
  }

  egress {
    description = "Allow all outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "build-attestable-ami-sg"
  }
}

# Generate SSH key pair for AMI build instance
resource "tls_private_key" "this" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

# Create AWS key pair from generated SSH key
resource "aws_key_pair" "this" {
  key_name   = "build-attestable-ami-key"
  public_key = tls_private_key.this.public_key_openssh

  tags = {
    Name = "build-attestable-ami-key"
  }
}

# IAM assume role policy for EC2
data "aws_iam_policy_document" "assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

# IAM role for AMI build instance
resource "aws_iam_role" "this" {
  name               = "build-attestable-ami-instance-role"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json

  tags = {
    Name = "build-attestable-ami-instance-role"
  }
}

# IAM policy for EC2 snapshot and image operations
data "aws_iam_policy_document" "this" {
  statement {
    effect = "Allow"

    actions = [
      "ec2:CreateSnapshot",
      "ec2:DescribeSnapshots",
      "ec2:ModifySnapshotAttribute",
      "ec2:CreateTags",
      "ec2:RegisterImage",
      "ec2:DescribeImages"
    ]

    resources = ["*"]
  }

  statement {
    effect = "Allow"

    actions = [
      "ebs:StartSnapshot",
      "ebs:PutSnapshotBlock",
      "ebs:CompleteSnapshot"
    ]

    resources = ["*"]
  }
}

# Attach policy to IAM role
resource "aws_iam_role_policy" "this" {
  name   = "build-ami-instance-policy"
  role   = aws_iam_role.this.id
  policy = data.aws_iam_policy_document.this.json
}

# IAM instance profile for AMI build instance
resource "aws_iam_instance_profile" "this" {
  name = "build-attestable-ami-instance-profile"
  role = aws_iam_role.this.name

  tags = {
    Name = "build-attestable-ami-instance-profile"
  }
}

# AMI build instance
resource "aws_instance" "this" {
  ami                    = data.aws_ami.amazon_linux_2023.id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.this.id
  vpc_security_group_ids = [aws_security_group.this.id]
  iam_instance_profile   = aws_iam_instance_profile.this.name
  key_name               = aws_key_pair.this.key_name

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  root_block_device {
    volume_type = "gp3"
    volume_size = 30
    encrypted   = true
  }

  tags = {
    Name = "build-attestable-ami-instance"
  }
}
