#!/usr/bin/env python3
"""
Deployment Script

Deploy target EC2 instance from the attestable AMI
Deploy the supporting infrastructures
"""

import argparse
import json
import logging
from pathlib import Path
import subprocess
import sys
from urllib import request

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('deploy.log')
    ]
)
logger = logging.getLogger(__name__)

def get_user_public_ip() -> str:
    """
    Get the user's public IP address for SSH access configuration.
    
    Returns:
        Public IP address as a string
    """
    with request.urlopen('https://checkip.amazonaws.com', timeout=5) as response:
        my_ip = response.read().decode('utf-8').strip()
        logger.info(f"Detected my public IP: {my_ip}")
        return my_ip

def terraform_init(terraform_dir: str) -> None:
    """
    Initialize Terraform in the specified directory.
    
    Downloads required providers and prepares the working directory.
    
    Args:
        terraform_dir: Path to Terraform configuration directory
    
    Raises:
        RuntimeError: If terraform init fails
    """
    logger.info("Initializing Terraform...")
    
    terraform_path = Path(terraform_dir)
    if not terraform_path.exists():
        raise FileNotFoundError(f"Terraform directory not found: {terraform_dir}")
    
    # Run terraform init
    result = subprocess.run(
        ['terraform', 'init'],
        cwd=terraform_path,
        capture_output=True,
        text=True
    )
    
    # Log output
    if result.stdout:
        for line in result.stdout.split('\n'):
            if line.strip():
                logger.debug(f"  {line}")
    
    if result.returncode != 0:
        logger.error("Terraform init failed:")
        if result.stderr:
            for line in result.stderr.split('\n'):
                if line.strip():
                    logger.error(f"  {line}")
        raise RuntimeError(f"Terraform init failed with exit code {result.returncode}")
    
    logger.info("✓ Terraform initialized successfully")

def terraform_apply(
    terraform_dir: str,
    ami_build_result: dict,
    allowed_http_cidr: str,
    instance_type: str
) -> dict:
    """
    Apply Terraform configuration to provision infrastructure.
    
    Args:
        terraform_dir: Path to Terraform configuration directory
        ami_build_result: AMI build result containing AMI ID
        allowed_http_cidr: CIDR block for HTTP access
        instance_type: EC2 instance type
    
    Returns:
        dict object with deployed resource details
    
    Raises:
        RuntimeError: If terraform apply fails
    """
    logger.info("Applying Terraform configuration (this may take 5-8 minutes)...")
    
    terraform_path = Path(terraform_dir)
    
    # Prepare Terraform variables
    tf_vars = {
        'attestable_ami_id': ami_build_result['ami_id'],
        'instance_type': instance_type,
        'allowed_http_cidr': allowed_http_cidr,
        'aws_region': ami_build_result['region']
    }
    
    logger.info("Terraform variables:")
    for key, value in tf_vars.items():
        logger.info(f"  {key}: {value}")
    
    # Build command
    cmd = ['terraform', 'apply', '-auto-approve']
    for key, value in tf_vars.items():
        cmd.extend(['-var', f'{key}={value}'])
    
    # Run terraform apply
    result = subprocess.run(
        cmd,
        cwd=terraform_path,
        capture_output=True,
        text=True
    )
    
    # Log output
    if result.stdout:
        logger.info("Terraform apply output:")
        for line in result.stdout.split('\n'):
            if line.strip():
                logger.info(f"  {line}")
    
    if result.returncode != 0:
        logger.error("Terraform apply failed:")
        if result.stderr:
            for line in result.stderr.split('\n'):
                if line.strip():
                    logger.error(f"  {line}")
        raise RuntimeError(f"Terraform apply failed with exit code {result.returncode}")
    
    logger.info("✓ Infrastructure provisioned successfully")
    
    # Retrieve Terraform outputs
    logger.info("Retrieving Terraform outputs...")
    result = subprocess.run(
        ['terraform', 'output', '-json'],
        cwd=terraform_path,
        capture_output=True,
        text=True
    )
    
    if result.returncode != 0:
        logger.error("Failed to retrieve Terraform outputs:")
        if result.stderr:
            for line in result.stderr.split('\n'):
                if line.strip():
                    logger.error(f"  {line}")
        raise RuntimeError("Failed to retrieve Terraform outputs")
    
    # Parse outputs
    try:
        outputs = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Failed to parse Terraform outputs: {e}")
    
    logger.info("✓ Infrastructure state retrieved successfully")
    
    return outputs

def load_terraform_output(
    raw_terraform_output: dict
) -> dict:
    """
    Extract the value from raw terraform output

    Args:
        terraform_output (dict): Raw terraform output from terraform command

    Returns:
        dict: Dict with each terraform output value extracted
    """

    terraform_output = {}

    for k, v in raw_terraform_output.items():
        # Extract value from each output item
        if "value" in v:
            terraform_output[k] = v["value"]

    return terraform_output

def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description='Deploy infrastructure for attesable EC2 instance'
    )
    
    parser.add_argument(
        '--ami-build-result',
        type=str,
        default='ami_build_result.json',
        help='Path to AMI build result JSON file'
    )
    
    parser.add_argument(
        '--instance-type',
        type=str,
        default='c5.9xlarge',
        help='EC2 instance type (must be NitroTPM-compatible, default: c5.9xlarge)'
    )
    
    parser.add_argument(
        '--output-file',
        type=str,
        default='infrastructure_state.json',
        help='Output file for infrastructure state (default: infrastructure_state.json)'
    )
    
    return parser.parse_args()

def main() -> int:
    """Main entry point."""
    args = parse_arguments()

    terraform_dir = "terraform/deploy"
    
    logger.info("=" * 80)
    logger.info("Starting Infrastructure Deployment")
    logger.info("=" * 80)
    logger.info(f"AMI Build Result: {args.ami_build_result}")
    logger.info(f"Instance Type: {args.instance_type}")
    logger.info(f"Output File: {args.output_file}")
    
    try:
        # Load AMI build result
        logger.info("")
        logger.info("=" * 80)
        logger.info("Loading AMI Build Result")
        logger.info("=" * 80)
        
        if not Path(args.ami_build_result).exists():
            raise FileNotFoundError(f"AMI build result file not found: {args.ami_build_result}")
        
        try:
            with open(args.ami_build_result, "r") as f:
                ami_build_result = json.loads(f.read())
        except Exception as e:
            logger.error("Failed to read AMI build result file")
            raise RuntimeError(f"Failed to read AMI build result file: {e}")

        logger.info(f"AMI ID: {ami_build_result['ami_id']}")
        logger.info(f"Snapshot ID: {ami_build_result['snapshot_id']}")
        logger.info(f"Region: {ami_build_result['region']}")
        
        # Get my public IP for whitelisting
        my_public_ip = get_user_public_ip()
        allowed_http_cidr = f"{my_public_ip}/32"
        
        logger.info(f"Allowed HTTP CIDR: {allowed_http_cidr}")
        
        # Initialize Terraform
        logger.info("")
        logger.info("=" * 80)
        logger.info("Initializing Terraform")
        logger.info("=" * 80)
        
        terraform_init(terraform_dir)
        
        # Deploy infrastructure
        logger.info("")
        logger.info("=" * 80)
        logger.info("Deploying Infrastructure")
        logger.info("=" * 80)
        
        raw_terraform_output = terraform_apply(
            terraform_dir,
            ami_build_result,
            allowed_http_cidr,
            args.instance_type
        )

        # Extract values from terrafrom output
        terraform_output = load_terraform_output(raw_terraform_output)
        
        # Save infrastructure state
        logger.info("")
        logger.info("=" * 80)
        logger.info("Saving Infrastructure State")
        logger.info("=" * 80)
        
        try:
            with open(args.output_file, "w") as f:
                f.write(json.dumps(terraform_output, indent=2))
        except Exception as e:
            logger.error("Failed to save infrastructure state")
            raise RuntimeError(f"Failed to save infrastructure state: {e}")
        
        # Success summary
        logger.info("")
        logger.info("=" * 80)
        logger.info("INFRASTRUCTURE DEPLOYMENT COMPLETED SUCCESSFULLY")
        logger.info("=" * 80)
        logger.info(f"Instance ID: {terraform_output['instance_id']}")
        logger.info(f"Instance Public IP: {terraform_output['instance_public_ip']}")
        logger.info(f"Attestation API URL: {terraform_output['attestation_api_url']}")
        logger.info(f"VPC ID: {terraform_output['vpc_id']}")
        logger.info(f"Subnet ID: {terraform_output['subnet_id']}")
        logger.info(f"Security Group ID: {terraform_output['security_group_id']}")
        logger.info(f"Infrastructure state saved to: {args.output_file}")
        logger.info("=" * 80)
        
        return 0
        
    except Exception as e:
        logger.error("")
        logger.error("=" * 80)
        logger.error("INFRASTRUCTURE DEPLOYMENT FAILED")
        logger.error("=" * 80)
        logger.error(f"Error: {e}")
        logger.error("=" * 80)
        logger.error("You may need to run 'terraform destroy' to clean up partial resources")
        return 1

if __name__ == '__main__':
    sys.exit(main())
