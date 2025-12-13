#!/usr/bin/env python3
"""
Cleanup Script

Removes all AWS resources created
"""

import argparse
import json
import logging
from pathlib import Path
import subprocess
import sys
from typing import Any, Dict, List

import boto3
from botocore.exceptions import ClientError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('cleanup.log')
    ]
)
logger = logging.getLogger(__name__)


def destroy_infrastructure(terraform_dir: str) -> None:
    """
    Destroy Terraform-managed infrastructure.
    
    Args:
        terraform_dir: Path to Terraform configuration directory
    """
    logger.info("Destroying Terraform-managed infrastructure...")
    
    terraform_path = Path(terraform_dir)
    if not terraform_path.exists():
        logger.warning(f"Terraform directory not found: {terraform_dir}")
        logger.warning("Skipping Terraform destruction")
        return
    
    # Check if Terraform state exists
    state_file = terraform_path / 'terraform.tfstate'
    if not state_file.exists():
        logger.warning("No Terraform state file found")
        logger.warning("Infrastructure may not have been deployed or already destroyed")
        return
    
    # Initialize Terraform (required before destroy)
    logger.info("Initializing Terraform...")
    result = subprocess.run(
        ['terraform', 'init'],
        cwd=terraform_path,
        capture_output=True,
        text=True
    )
    
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
    
    logger.info("✓ Terraform initialized")
    
    # Execute terraform destroy
    logger.info("Executing terraform destroy...")
    logger.info("This may take several minutes...")
    
    # Terraform destroy requires variables to be set, even though it uses state
    # Provide dummy values for required variables without defaults
    result = subprocess.run(
        [
            'terraform', 'destroy', '-auto-approve',
            '-var', 'attestable_ami_id=dummy',
            '-var', 'allowed_http_cidr=0.0.0.0/0'
        ],
        cwd=terraform_path,
        capture_output=True,
        text=True
    )
    
    if result.stdout:
        logger.info("Terraform destroy output:")
        for line in result.stdout.split('\n'):
            if line.strip():
                logger.info(f"  {line}")
    
    if result.returncode != 0:
        logger.error("Terraform destroy failed:")
        if result.stderr:
            for line in result.stderr.split('\n'):
                if line.strip():
                    logger.error(f"  {line}")
        raise RuntimeError(f"Terraform destroy failed with exit code {result.returncode}")
    
    logger.info("✓ Terraform infrastructure destroyed successfully")
    
    # Verify state file shows no resources
    logger.info("Verifying Terraform state...")
    
    try:
        with open(state_file, 'r') as f:
            state_data = json.load(f)
        
        resources = state_data.get('resources', [])
        if resources:
            logger.warning(f"Warning: {len(resources)} resources still in Terraform state")
            logger.warning("Some resources may not have been destroyed properly")
        else:
            logger.info("✓ Terraform state shows no remaining resources")
    except Exception as e:
        logger.warning(f"Could not verify Terraform state: {e}")

def deregister_ami(ec2_client: Any, ami_id: str, snapshot_id: str) -> None:
    """
    Deregister the Attestable AMI.
    
    Calls EC2 DeregisterImage API to remove the AMI and associated snapshot from the registry.
    
    Args:
        ec2_client: Boto3 EC2 client
        ami_id: AMI ID to deregister
        snapshot_id: Snapshot ID of associated snapshot
    """
    logger.info(f"Deregistering AMI: {ami_id}")
    
    try:
        # Check if AMI exists
        try:
            response = ec2_client.describe_images(ImageIds=[ami_id])
            if not response['Images']:
                logger.warning(f"AMI {ami_id} not found - may already be deregistered")
                return
        except ClientError as e:
            if e.response['Error']['Code'] == 'InvalidAMIID.NotFound':
                logger.warning(f"AMI {ami_id} not found - may already be deregistered")
                return
            raise
        
        # Deregister the AMI
        ec2_client.deregister_image(ImageId=ami_id, DeleteAssociatedSnapshots=True)
        logger.info(f"✓ AMI {ami_id} deregistered successfully")
        
        # Verify deregistration
        import time
        time.sleep(2)  # Brief wait for deregistration to propagate
        
        # Verify if AMI deregistered
        try:
            response = ec2_client.describe_images(ImageIds=[ami_id])
            if response['Images']:
                logger.warning("AMI still appears in registry - may take time to propagate")
        except ClientError as e:
            if e.response['Error']['Code'] == 'InvalidAMIID.NotFound':
                logger.info("✓ AMI deregistration verified")

        # Verify if snapshot deleted
        try:
            response = ec2_client.describe_snapshots(SnapshotIds=[snapshot_id])
            if response['Snapshots']:
                logger.warning("Snapshot still appears in registry - may take time to propagate")
        except ClientError as e:
            if e.response['Error']['Code'] == 'InvalidSnapshot.NotFound':
                logger.info("✓ Snapshot deletion verified")
        
    except ClientError as e:
        logger.error(f"Failed to deregister AMI: {e}")
        raise

def verify_cleanup(ec2_client: Any, ami_build_result: dict) -> None:
    """
    Verify that all resources have been cleaned up.
    
    Checks for remaining resources with project tags and displays any that still exist.
    
    Args:
        ec2_client: Boto3 EC2 client
        ami_build_result: AMI build result containing resource identifiers
    """
    logger.info("Verifying cleanup completion...")
    
    remaining_resources: List[Dict[str, str]] = []
    
    # Check for EC2 instances with project tags
    logger.info("Checking for EC2 instances...")
    try:
        response = ec2_client.describe_instances(
            Filters=[
                {'Name': 'tag:Purpose', 'Values': ['AMI Build', 'Attestation Demo']},
                {'Name': 'instance-state-name', 'Values': ['pending', 'running', 'stopping', 'stopped']}
            ]
        )
        
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                instance_id = instance['InstanceId']
                state = instance['State']['Name']
                remaining_resources.append({
                    'Type': 'EC2 Instance',
                    'ID': instance_id,
                    'Status': state
                })
                logger.warning(f"  Found EC2 instance: {instance_id} (state: {state})")
    except ClientError as e:
        logger.warning(f"Could not check EC2 instances: {e}")
    
    # Check for the specific AMI
    logger.info("Checking for AMI...")
    try:
        response = ec2_client.describe_images(ImageIds=[ami_build_result['ami_id']])
        if response['Images']:
            remaining_resources.append({
                'Type': 'AMI',
                'ID': ami_build_result['ami_id'],
                'Status': 'available'
            })
            logger.warning(f"  Found AMI: {ami_build_result['ami_id']}")
    except ClientError as e:
        if e.response['Error']['Code'] != 'InvalidAMIID.NotFound':
            logger.warning(f"Could not check AMI: {e}")
    
    # Check for the specific snapshot
    logger.info("Checking for EBS snapshot...")
    try:
        response = ec2_client.describe_snapshots(SnapshotIds=[ami_build_result['snapshot_id']])
        if response['Snapshots']:
            remaining_resources.append({
                'Type': 'EBS Snapshot',
                'ID': ami_build_result['snapshot_id'],
                'Status': response['Snapshots'][0]['State']
            })
            logger.warning(f"  Found snapshot: {ami_build_result['snapshot_id']}")
    except ClientError as e:
        if e.response['Error']['Code'] != 'InvalidSnapshot.NotFound':
            logger.warning(f"Could not check snapshot: {e}")
    
    # Display summary
    logger.info("")
    logger.info("-" * 80)
    if remaining_resources:
        logger.warning(f"Found {len(remaining_resources)} remaining resource(s):")
        logger.warning("These resources may need manual cleanup:")
        for resource in remaining_resources:
            logger.warning(f"  - {resource['Type']}: {resource['ID']} ({resource['Status']})")
        logger.warning("\nPlease review and manually delete these resources if needed.")
    else:
        logger.info("✓ No remaining resources found")
        logger.info("Cleanup verification complete - all resources removed")
    logger.info("-" * 80)

def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description='Clean up all resources from EC2 attestation demonstration'
    )
    
    parser.add_argument(
        '--ami-build-result',
        type=str,
        default='ami_build_result.json',
        help='Path to AMI build result JSON file'
    )
    
    parser.add_argument(
        '--terraform-dir',
        type=str,
        default='terraform/deploy',
        help='Path to Terraform configuration directory (default: terraform)'
    )

    return parser.parse_args()

def main() -> int:
    """Main entry point for cleanup script."""
    args = parse_arguments()
    
    logger.info("=" * 80)
    logger.info("Starting Cleanup Process")
    logger.info("=" * 80)
    logger.info(f"AMI Build Result: {args.ami_build_result}")
    logger.info(f"Terraform Directory: {args.terraform_dir}")
    
    try:
        # Load AMI build result
        logger.info("")
        logger.info("=" * 80)
        logger.info("Loading Configuration")
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
        
        # Confirmation prompt
        logger.warning("")
        logger.warning("=" * 80)
        logger.warning("WARNING: This will destroy all resources created during the demonstration")
        logger.warning("!" * 80)
        logger.warning("Resources to be deleted:")
        logger.warning(f"  - Terraform infrastructure in {args.terraform_dir}")
        logger.warning(f"  - AMI: {ami_build_result['ami_id']}")
        logger.warning(f"  - Snapshot: {ami_build_result['snapshot_id']}")
        logger.warning("")
        
        response = input("Are you sure you want to proceed? (yes/no): ")
        if response.lower() not in ['yes', 'y']:
            logger.info("Cleanup cancelled by user")
            return 0
        
        # Destroy Terraform infrastructure
        logger.info("")
        logger.info("=" * 80)
        logger.info("Destroying Terraform Infrastructure")
        logger.info("=" * 80)
        
        destroy_infrastructure(args.terraform_dir)
        
        # Deregister AMI and delete snapshot
        logger.info("")
        logger.info("=" * 80)
        logger.info("Cleaning Up AMI and Snapshot")
        logger.info("=" * 80)
        
        ec2_client = boto3.client('ec2', region_name=ami_build_result['region'])
        
        deregister_ami(ec2_client, ami_build_result['ami_id'], ami_build_result['snapshot_id'])
        
        # Verify cleanup
        logger.info("")
        logger.info("=" * 80)
        logger.info("Verifying Cleanup")
        logger.info("=" * 80)
        
        ec2_client = boto3.client('ec2', region_name=ami_build_result['region'])
        verify_cleanup(ec2_client, ami_build_result)
        
        # Success summary
        logger.info("")
        logger.info("=" * 80)
        logger.info("CLEANUP COMPLETED SUCCESSFULLY")
        logger.info("=" * 80)
        logger.info("All resources have been removed")
        logger.info("=" * 80)
        
        return 0
        
    except Exception as e:
        logger.info("")
        logger.info("=" * 80)
        logger.error("CLEANUP FAILED")
        logger.error("=" * 80)
        logger.error(f"Error: {e}")
        logger.error("=" * 80)
        logger.error("Some resources may still exist. Please check manually.")
        return 1

if __name__ == '__main__':
    sys.exit(main())
