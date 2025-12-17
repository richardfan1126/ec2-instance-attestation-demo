#!/usr/bin/env python3
"""
AMI Build Script

Use an EC2 instance to pull pre-built KIWI image from GitHub Container Registry,
verify its signature, and transform it into an AMI.
"""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import logging
import tempfile
import time
from typing import Any, Optional, Tuple
from urllib import request

import boto3
import paramiko
from botocore.exceptions import ClientError, WaiterError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('build_ami.log')
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

def provision_ami_build_instance(
    region: str,
    instance_type: str,
) -> Tuple[str, str, str]:
    """
    Provision AMI build EC2 instance using Terraform.
    
    Args:
        region: AWS region for the instance
        instance_type: EC2 instance type
    
    Returns:
        Tuple of (instance_id, instance_public_ip, ssh_private_key_pem)
    """
    logger.info("Provisioning AMI build EC2 instance with Terraform...")
    
    my_public_ip = get_user_public_ip()
    allowed_ssh_cidr = f"{my_public_ip}/32"
    
    logger.info(f"  Region: {region}")
    logger.info(f"  Instance Type: {instance_type}")
    logger.info(f"  Allowed SSH CIDR: {allowed_ssh_cidr}")
    
    # Initialize Terraform
    tf_working_dir = Path(__file__).parent.parent / 'terraform' / 'build-ami'
    
    # Initialize Terraform
    logger.info("Initializing Terraform...")
    result = subprocess.run(
        ['terraform', 'init'],
        cwd=tf_working_dir,
        capture_output=True,
        text=True
    )
    
    if result.returncode != 0:
        logger.error(f"Terraform init failed: {result.stderr}")
        raise RuntimeError(f"Terraform init failed: {result.stderr}")
    
    logger.info("Terraform initialized successfully")
    
    # Prepare variables
    tf_vars = {
        'region': region,
        'instance_type': instance_type,
        'allowed_ssh_cidr': allowed_ssh_cidr
    }
    
    # Apply Terraform configuration
    logger.info("Applying Terraform configuration (this may take 2-3 minutes)...")
    cmd = ['terraform', 'apply', '-auto-approve']
    for key, value in tf_vars.items():
        cmd.extend(['-var', f'{key}={value}'])
    
    result = subprocess.run(
        cmd,
        cwd=tf_working_dir,
        capture_output=True,
        text=True
    )
    
    if result.returncode != 0:
        logger.error(f"Terraform apply failed: {result.stderr}")
        raise RuntimeError(f"Terraform apply failed: {result.stderr}")
    
    logger.info("AMI build infrastructure provisioned successfully")
    
    # Retrieve outputs
    logger.info("Retrieving Terraform outputs...")
    result = subprocess.run(
        ['terraform', 'output', '-json'],
        cwd=tf_working_dir,
        capture_output=True,
        text=True
    )
    
    if result.returncode != 0:
        raise RuntimeError("Failed to retrieve Terraform outputs")
    
    outputs = json.loads(result.stdout)
    
    # Parse outputs
    instance_id = outputs['instance_id']['value']
    instance_public_ip = outputs['instance_public_ip']['value']
    ssh_private_key = outputs['ssh_private_key']['value']
    
    logger.info(f"AMI build instance provisioned: {instance_id}")
    logger.info(f"Public IP: {instance_public_ip}")
    
    return instance_id, instance_public_ip, ssh_private_key

def save_ssh_private_key(ssh_private_key_pem: str) -> str:
    """
    Save SSH private key for SSH client to connect to the instance
    
    Args:
        ssh_private_key_pem: SSH private key in PEM format
    
    Returns:
        Path to the temporary key file
    """
    # Create temporary file
    fd, key_path = tempfile.mkstemp(suffix='.pem', prefix='import-key-')
    
    try:
        # Write key to file
        with os.fdopen(fd, 'w') as f:
            f.write(ssh_private_key_pem)
        
        # Set secure permissions (600 - owner read/write only)
        os.chmod(key_path, 0o600)
        
        logger.info(f"SSH private key saved to: {key_path}")
        return key_path
        
    except Exception as e:
        # Clean up on error
        try:
            os.close(fd)
        except Exception:
            pass
        try:
            os.unlink(key_path)
        except Exception:
            pass
        raise RuntimeError(f"Failed to save SSH private key: {e}")

def wait_for_instance_ready(ec2_client: Any, instance_id: str, timeout: int = 300) -> None:
    """
    Wait for the instance to be running and status checks to pass.
    
    Args:
        ec2_client: Boto3 EC2 client
        instance_id: Instance ID to wait for
        timeout: Maximum time to wait in seconds
    """
    logger.info(f"Waiting for instance {instance_id} to be ready...")
    
    try:
        # Wait for instance to be running
        waiter = ec2_client.get_waiter('instance_running')
        waiter.wait(
            InstanceIds=[instance_id],
            WaiterConfig={'Delay': 15, 'MaxAttempts': timeout // 15}
        )
        logger.info("Instance is running")
        
        # Wait for status checks to pass
        waiter = ec2_client.get_waiter('instance_status_ok')
        waiter.wait(
            InstanceIds=[instance_id],
            WaiterConfig={'Delay': 15, 'MaxAttempts': timeout // 15}
        )
        logger.info("Instance status checks passed")
        
    except WaiterError as e:
        logger.error(f"Instance failed to become ready: {e}")
        raise

def verify_ssh_connectivity(
    host: str,
    username: str,
    key_filename: str,
    max_attempts: int = 10,
    delay: int = 30
) -> paramiko.SSHClient:
    """
    Verify SSH connectivity to the instance
    
    Args:
        host: Instance public IP address
        username: SSH username (ec2-user for AL2023)
        key_filename: Path to SSH private key file
        max_attempts: Maximum number of connection attempts
        delay: Delay between attempts in seconds
    
    Returns:
        Connected paramiko SSHClient
    """
    logger.info(f"Verifying SSH connectivity to {host}...")
    
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    for attempt in range(1, max_attempts + 1):
        try:
            logger.info(f"SSH connection attempt {attempt}/{max_attempts}")
            ssh_client.connect(
                hostname=host,
                username=username,
                key_filename=key_filename,
                timeout=10,
                banner_timeout=10
            )
            # Enable keepalive to prevent connection timeouts during long operations
            ssh_client.get_transport().set_keepalive(30)
            logger.info("SSH connection established successfully")
            return ssh_client
        except (paramiko.SSHException, OSError) as e:
            if attempt < max_attempts:
                logger.warning(f"SSH connection failed: {e}. Retrying in {delay}s...")
                time.sleep(delay)
            else:
                logger.error(f"Failed to establish SSH connection after {max_attempts} attempts")
                raise
    
    raise RuntimeError("Failed to establish SSH connection")

def execute_remote_command(
    ssh_client: paramiko.SSHClient,
    command: str,
    stream_output: bool = True
) -> tuple[int, str, str]:
    """
    Execute a command on the remote instance via SSH.
    
    Args:
        ssh_client: Connected paramiko SSHClient
        command: Command to execute
        stream_output: Whether to stream output to logger
    
    Returns:
        Tuple of (exit_code, stdout, stderr)
    """
    logger.debug(f"Executing command: {command}")
    
    stdin, stdout, stderr = ssh_client.exec_command(command, get_pty=False)
    
    stdout_lines = []
    stderr_lines = []
    
    # Set channels to non-blocking to avoid deadlock
    stdout.channel.setblocking(0)
    stderr.channel.setblocking(0)
    
    # Read stdout and stderr concurrently to avoid buffer deadlock
    while not stdout.channel.exit_status_ready():
        # Wait for data to be available
        if stdout.channel.recv_ready():
            data = stdout.channel.recv(4096).decode('utf-8', errors='replace')
            for line in data.splitlines():
                line = line.rstrip()
                if line:
                    stdout_lines.append(line)
                    if stream_output:
                        logger.info(f"  {line}")
        
        if stderr.channel.recv_stderr_ready():
            data = stderr.channel.recv_stderr(4096).decode('utf-8', errors='replace')
            for line in data.splitlines():
                line = line.rstrip()
                if line:
                    stderr_lines.append(line)
                    if stream_output:
                        logger.warning(f"  {line}")

        time.sleep(0.1)
    
    # Read any remaining data after command completes
    while stdout.channel.recv_ready():
        data = stdout.channel.recv(4096).decode('utf-8', errors='replace')
        for line in data.splitlines():
            line = line.rstrip()
            if line:
                stdout_lines.append(line)
                if stream_output:
                    logger.info(f"  {line}")
    
    while stderr.channel.recv_stderr_ready():
        data = stderr.channel.recv_stderr(4096).decode('utf-8', errors='replace')
        for line in data.splitlines():
            line = line.rstrip()
            if line:
                stderr_lines.append(line)
                if stream_output:
                    logger.warning(f"  {line}")
    
    exit_code = stdout.channel.recv_exit_status()
    
    return exit_code, '\n'.join(stdout_lines), '\n'.join(stderr_lines)

def install_system_dependencies(ssh_client: paramiko.SSHClient) -> None:
    """
    Install system dependencies on the instance via SSH.
    
    Installs git, gcc, and Rust toolchain (cargo) required for building coldsnap.
    
    Args:
        ssh_client: Connected paramiko SSHClient
    """
    logger.info("Installing system dependencies...")
    
    # Install git and gcc
    exit_code, _, stderr = execute_remote_command(
        ssh_client,
        "sudo dnf install -y git gcc",
        stream_output=True
    )
    if exit_code != 0:
        raise RuntimeError(f"Failed to install system packages: {stderr}")
    
    logger.info("  ✓ git and gcc installed")
    
    # Install Rust toolchain
    logger.info("Installing Rust toolchain...")
    exit_code, _, stderr = execute_remote_command(
        ssh_client,
        'curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y',
        stream_output=True
    )
    if exit_code != 0:
        raise RuntimeError(f"Failed to install Rust: {stderr}")
    
    logger.info("  ✓ Rust toolchain installed")

def install_oras(ssh_client: paramiko.SSHClient) -> None:
    """
    Install ORAS CLI on the EC2 instance via SSH.
    
    Downloads and installs ORAS from GitHub releases.
    
    Args:
        ssh_client: Connected paramiko SSHClient
    """
    logger.info("Installing ORAS CLI...")
    
    # ORAS version to install
    oras_version = "1.3.0"
    
    # Download ORAS
    download_cmd = f"""
    cd /tmp && \
    curl -LO "https://github.com/oras-project/oras/releases/download/v{oras_version}/oras_{oras_version}_linux_amd64.tar.gz" && \
    tar -xzf oras_{oras_version}_linux_amd64.tar.gz && \
    sudo mv oras /usr/local/bin/ && \
    rm oras_{oras_version}_linux_amd64.tar.gz
    """
    
    exit_code, stdout, stderr = execute_remote_command(ssh_client, download_cmd)
    
    if exit_code != 0:
        raise RuntimeError(f"Failed to install ORAS: {stderr}")
    
    # Verify installation
    exit_code, stdout, _ = execute_remote_command(
        ssh_client,
        "oras version",
        stream_output=False
    )
    
    if exit_code == 0:
        logger.info(f"  ✓ ORAS installed: {stdout.strip()}")
    else:
        raise RuntimeError("Failed to verify ORAS installation")

def install_github_cli(ssh_client: paramiko.SSHClient) -> None:
    """
    Install GitHub CLI on the instance via SSH.
    
    Args:
        ssh_client: Connected paramiko SSHClient
    """
    logger.info("Installing GitHub CLI...")
    
    # Install GitHub cli using yun
    install_cmd = f"""
    sudo dnf install dnf-utils -y && \
    sudo dnf config-manager --add-repo https://cli.github.com/packages/rpm/gh-cli.repo && \
    sudo dnf install gh -y
    """
    
    exit_code, stdout, stderr = execute_remote_command(ssh_client, install_cmd)
    
    if exit_code != 0:
        raise RuntimeError(f"Failed to install GitHub CLI: {stderr}")
    
    # Verify installation
    exit_code, stdout, _ = execute_remote_command(
        ssh_client,
        "gh version",
        stream_output=False
    )
    
    if exit_code == 0:
        logger.info(f"  ✓ GitHub CLI installed: {stdout.strip()}")
    else:
        raise RuntimeError("Failed to verify GitHub CLI installation")

def install_coldsnap(ssh_client: paramiko.SSHClient) -> None:
    """
    Install coldsnap on the instance via SSH.
    
    Builds and installs coldsnap from the AWS Labs GitHub repository using Cargo.

    See: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/build-sample-ami.html
    
    Args:
        ssh_client: Connected paramiko SSHClient
    """
    logger.info("Installing coldsnap...")
    
    # Clone coldsnap repository
    exit_code, _, stderr = execute_remote_command(
        ssh_client,
        "git clone https://github.com/awslabs/coldsnap.git"
    )
    if exit_code != 0:
        raise RuntimeError(f"Failed to clone coldsnap repository: {stderr}")
    
    # Build and install coldsnap using Cargo
    exit_code, _, stderr = execute_remote_command(
        ssh_client,
        "cd coldsnap && cargo install --locked coldsnap",
        stream_output=True
    )
    if exit_code != 0:
        raise RuntimeError(f"Failed to install coldsnap: {stderr}")
    
    # Verify installation
    exit_code, stdout, _ = execute_remote_command(
        ssh_client,
        "/home/ec2-user/.cargo/bin/coldsnap --help",
        stream_output=False
    )
    
    if exit_code == 0:
        logger.info(f"  ✓ coldsnap installed successfully")
    else:
        raise RuntimeError("Failed to verify coldsnap installation")

def pull_artifact_from_ghcr(ssh_client: paramiko.SSHClient, artifact_ref: str) -> dict:
    """
    Pull artifact bundle from GitHub Container Registry using ORAS.
    
    Executes ORAS pull command on the instance to download the artifact bundle
    containing the KIWI image and PCR measurements.
    
    Args:
        ssh_client: Connected paramiko SSHClient
        artifact_ref: GitHub Container Registry artifact reference
    
    Returns:
        Dictionray of PCR measurements of the image
    """
    logger.info(f"Pulling artifact from GHCR: {artifact_ref}")
    
    # Create working directory for artifacts
    exit_code, _, stderr = execute_remote_command(
        ssh_client,
        "mkdir -p ~/artifacts && cd ~/artifacts",
        stream_output=False
    )
    
    if exit_code != 0:
        raise RuntimeError(f"Failed to create artifacts directory: {stderr}")
    
    # Pull artifacts using ORAS (no authentication required for public repos)
    logger.info("Downloading artifacts with ORAS...")
    pull_cmd = f"cd ~/artifacts && oras pull {artifact_ref}"
    
    exit_code, stdout, stderr = execute_remote_command(ssh_client, pull_cmd, stream_output=True)
    
    if exit_code != 0:
        raise RuntimeError(f"ORAS pull failed: {stderr}")
    
    logger.info("Artifacts downloaded successfully")
    
    # Verify artifacts are present in build-output directory
    logger.info("Verifying downloaded artifacts...")
    exit_code, stdout, stderr = execute_remote_command(
        ssh_client,
        "cd ~/artifacts/build-output && ls -lh",
        stream_output=False
    )
    
    if exit_code != 0:
        raise RuntimeError(f"Failed to list artifacts in build-output: {stderr}")
    
    logger.info(f"Downloaded artifacts:\n{stdout}")
    
    # Check for required files in build-output directory
    exit_code, _, _ = execute_remote_command(
        ssh_client,
        "test -f ~/artifacts/build-output/pcr_measurements.json",
        stream_output=False
    )
    
    if exit_code != 0:
        raise RuntimeError("pcr_measurements.json not found in build-output directory")
    
    exit_code, stdout, _ = execute_remote_command(
        ssh_client,
        "cd ~/artifacts/build-output && ls *.raw",
        stream_output=False
    )
    
    if exit_code != 0:
        raise RuntimeError("Raw disk image (.raw file) not found in build-output directory")
    
    logger.info("All required artifacts verified successfully")

    exit_code, stdout, _ = execute_remote_command(
        ssh_client,
        "cat ~/artifacts/build-output/pcr_measurements.json",
        stream_output=False
    )
    
    if exit_code != 0:
        raise RuntimeError("Failed getting pcr_measurements.json content")
    
    try:
        pcr_measurements = json.loads(stdout)
    except Exception as e:
        raise RuntimeError(f"Failed parsing pcr_measurements.json content: {e}")

    return pcr_measurements

def verify_artifact_signature(
    ssh_client: paramiko.SSHClient,
    artifact_ref: str,
) -> bool:
    """
    Verify artifact signature using gh attestation.
    
    Args:
        ssh_client: Connected paramiko SSHClient
        artifact_ref: GitHub Container Registry artifact reference
    
    Returns:
        True if verification succeeds, False otherwise
    """
    logger.info("Verifying artifact signature with gh attestation ...")
    
    # Extract repository information from artifact reference
    # Format: ghcr.io/owner/repo:tag or ghcr.io/owner/repo:tag@sha256:digest
    parts = artifact_ref.replace('ghcr.io/', '').split(':')[0].split('/')
    if len(parts) >= 2:
        owner = parts[0]
        repo = parts[1]
        identity = f"{owner}/{repo}"
    else:
        logger.error("✗ Artifact signature verification FAILED")
        logger.error(f"Cannot determine identity from artifact path")
        return False
    
    logger.info(f"Using attestation identity: {identity}")

    verify_cmd = f"""
    # Extract the image digest using oras manifest
    DIGEST=$(oras manifest fetch {artifact_ref} | sha256sum | cut -d ' ' -f 1)

    # Download GitHub attestation bundle
    curl -sL "https://api.github.com/repos/{owner}/{repo}/attestations/sha256:${{DIGEST}}" \
        | jq -cr '.attestations[0].bundle' > bundle.json

    # Offline attestation verify
    # Set GH_FORCE_TTY=1 to force gh outputting result
    GH_FORCE_TTY=1 gh attestation verify oci://{artifact_ref} \
        -R {identity} \
        -b bundle.json
    """

    exit_code, stdout, stderr = execute_remote_command(
        ssh_client,
        verify_cmd,
        stream_output=True
    )
    
    if exit_code == 0:
        logger.info("✓ Artifact attestation verification SUCCEEDED")
        return True
    else:
        logger.error("✗ Artifact signature verification FAILED")
        logger.error(f"command output: {stderr}")
        return False

def upload_snapshot(ssh_client: paramiko.SSHClient, region: str) -> str:
    """
    Upload the raw disk image to an EBS snapshot using coldsnap.
    
    Args:
        ssh_client: Connected paramiko SSHClient
        region: AWS region for snapshot creation
    
    Returns:
        Snapshot ID string
    """
    logger.info("Uploading raw disk image to EBS snapshot...")
    
    # Find the raw disk image file in build-output directory
    exit_code, stdout, stderr = execute_remote_command(
        ssh_client,
        "cd ~/artifacts/build-output && ls *.raw",
        stream_output=False
    )
    
    if exit_code != 0:
        raise RuntimeError(f"Failed to find raw disk image: {stderr}")
    
    raw_image_path = f"~/artifacts/build-output/{stdout.strip()}"
    logger.info(f"Found raw disk image: {raw_image_path}")
    
    # Upload using coldsnap
    logger.info("Uploading snapshot with coldsnap (this may take several minutes)...")
    
    coldsnap_command = f"/home/ec2-user/.cargo/bin/coldsnap upload {raw_image_path}"
    exit_code, stdout, stderr = execute_remote_command(
        ssh_client,
        coldsnap_command,
        stream_output=True
    )
    
    if exit_code != 0:
        raise RuntimeError(f"coldsnap upload failed: {stderr}")
    
    # Parse snapshot ID from output
    snapshot_id = None
    for line in stdout.split('\n'):
        if 'snap-' in line:
            # Extract snapshot ID
            parts = line.split()
            for part in parts:
                if part.startswith('snap-'):
                    snapshot_id = part
                    break
            if snapshot_id:
                break
    
    if not snapshot_id:
        # Try to find it in the last line
        last_line = stdout.strip().split('\n')[-1]
        if last_line.startswith('snap-'):
            snapshot_id = last_line.strip()
    
    if not snapshot_id:
        raise RuntimeError(f"Failed to parse snapshot ID from coldsnap output: {stdout}")
    
    logger.info(f"Snapshot created successfully: {snapshot_id}")
    return snapshot_id

def register_ami(
    ec2_client: Any,
    snapshot_id: str,
    architecture: str,
    ami_name: str
) -> str:
    """
    Register an AMI with TPM 2.0 and UEFI boot mode.
    
    Args:
        ec2_client: Boto3 EC2 client
        snapshot_id: EBS snapshot ID
        architecture: CPU architecture (x86_64 or arm64)
        ami_name: Name for the AMI
    
    Returns:
        AMI ID string
    """
    logger.info("Registering AMI with TPM 2.0 and UEFI boot mode...")
    logger.info(f"  Snapshot: {snapshot_id}")
    logger.info(f"  Architecture: {architecture}")
    logger.info(f"  Name: {ami_name}")
    
    # Wait for snapshot to complete before registering AMI
    logger.info("Waiting for snapshot to complete...")
    try:
        waiter = ec2_client.get_waiter('snapshot_completed')
        waiter.wait(
            SnapshotIds=[snapshot_id],
            WaiterConfig={'Delay': 15, 'MaxAttempts': 40}  # Up to 10 minutes
        )
        logger.info("Snapshot completed successfully")
    except WaiterError as e:
        logger.error(f"Snapshot failed to complete: {e}")
        raise
    
    try:
        response = ec2_client.register_image(
            Name=ami_name,
            VirtualizationType='hvm',
            BootMode='uefi',
            Architecture=architecture,
            RootDeviceName='/dev/xvda',
            BlockDeviceMappings=[
                {
                    'DeviceName': '/dev/xvda',
                    'Ebs': {
                        'SnapshotId': snapshot_id
                    }
                }
            ],
            TpmSupport='v2.0',
            EnaSupport=True
        )
        
        ami_id = response['ImageId']
        logger.info(f"AMI registered successfully: {ami_id}")
        return ami_id
        
    except ClientError as e:
        logger.error(f"Failed to register AMI: {e}")
        raise

def cleanup_infrastructure(
    region: str,
    instance_type: str,
    allowed_ssh_cidr: str,
    ssh_key_path: str
) -> None:
    """
    Destroy all resources:
    - Terraform infratructure
    - SSH key
    
    Args:
        region: AWS region for the instance
        instance_type: EC2 instance type for the instance
        allowed_ssh_cidr: CIDR block for SSH access
    """
    logger.info("Destroying infrastructure with Terraform...")
    
    # Initialize Terraform
    tf_working_dir = Path(__file__).parent.parent / 'terraform' / 'build-ami'
    
    # Prepare variables (same as used during apply)
    tf_vars = {
        'region': region,
        'instance_type': instance_type,
        'allowed_ssh_cidr': allowed_ssh_cidr
    }
    
    # Destroy infrastructure with auto-approve flag and variables
    cmd = ['terraform', 'destroy', '-auto-approve']
    for key, value in tf_vars.items():
        cmd.extend(['-var', f'{key}={value}'])
    
    result = subprocess.run(
        cmd,
        cwd=tf_working_dir,
        capture_output=True,
        text=True
    )
    
    if result.returncode != 0:
        logger.error(f"Terraform destroy failed: {result.stderr}")
    
    logger.info("Infrastructure destroyed successfully")

    # Clean up temporary SSH key file
    if ssh_key_path and os.path.exists(ssh_key_path):
        try:
            os.unlink(ssh_key_path)
        except Exception:
            pass

def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description='Convert pre-built KIWI image from GitHub Container Registry and create AMI'
    )
    
    parser.add_argument(
        '--artifact-ref',
        type=str,
        required=True,
        help='GitHub Container Registry artifact reference (e.g., ghcr.io/owner/repo:tag@sha256:digest)'
    )
    
    parser.add_argument(
        '--region',
        type=str,
        default='us-east-1',
        help='AWS region for AMI creation (e.g., us-east-1)'
    )
    
    parser.add_argument(
        '--instance-type',
        type=str,
        default='c5.9xlarge',
        help='Instance type for AMI build instance (default: c5.9xlarge)'
    )
    
    parser.add_argument(
        '--output-file',
        type=str,
        default='ami_build_result.json',
        help='Output file for build result (default: ami_build_result.json)'
    )
    
    return parser.parse_args()

def main() -> int:
    """Main entry point for AMI build script."""
    args = parse_arguments()
    
    logger.info("=" * 80)
    logger.info("Starting AMI Build Process")
    logger.info("=" * 80)
    logger.info(f"Artifact Reference: {args.artifact_ref}")
    logger.info(f"Region: {args.region}")
    logger.info(f"Instance Type: {args.instance_type}")

    # Initialize AWS clients
    ec2_client = boto3.client('ec2', region_name=args.region)
    
    instance_id: Optional[str] = None
    ssh_client: Optional[paramiko.SSHClient] = None
    ssh_key_path: Optional[str] = None
    ami_id: Optional[str] = None
    snapshot_id: Optional[str] = None
    
    # Contruct allowed SSH CIDR from user public IP address
    my_public_ip = get_user_public_ip()
    allowed_ssh_cidr = f"{my_public_ip}/32"
    
    try:
        # Provision AMI build instance
        logger.info("")
        logger.info("=" * 80)
        logger.info("Provisioning AMI build instance")
        logger.info("=" * 80)
        
        instance_id, public_ip, ssh_private_key = provision_ami_build_instance(
            region=args.region,
            instance_type=args.instance_type,
        )

        # Save SSH private key to temporary file
        ssh_key_path = save_ssh_private_key(ssh_private_key)
        
        # Wait for instance to be ready
        wait_for_instance_ready(ec2_client, instance_id)
        
        # Verify SSH connectivity
        ssh_client = verify_ssh_connectivity(
            public_ip,
            'ec2-user',
            ssh_key_path
        )

        # Use SSH command to install tools on the instance
        logger.info("")
        logger.info("=" * 80)
        logger.info("Installing Tools on AMI build Instance")
        logger.info("=" * 80)
        
        install_system_dependencies(ssh_client)
        install_oras(ssh_client)
        install_github_cli(ssh_client)
        install_coldsnap(ssh_client)

        # Verify artifact signature
        logger.info("")
        logger.info("=" * 80)
        logger.info("Verifying Artifact Signature")
        logger.info("=" * 80)
        
        signature_valid = verify_artifact_signature(
            ssh_client,
            args.artifact_ref
        )

        if not signature_valid:
            # Signature verification failed - terminate without creating AMI
            logger.error("")
            logger.error("=" * 80)
            logger.error("SIGNATURE VERIFICATION FAILED")
            logger.error("=" * 80)
            logger.error("The artifact signature could not be verified.")
            logger.error("This could indicate:")
            logger.error("  - The artifact was not attested")
            logger.error("  - The signature does not match the expected GitHub identity")
            logger.error("  - The artifact has been tampered with")
            logger.error("")
            logger.error("AMI creation will NOT proceed.")
            logger.error("Please verify the artifact reference and try again.")
            logger.error("=" * 80)

            raise RuntimeError("SIGNATURE VERIFICATION FAILED")

        # Pull artifact from GHCR
        # Get PCR measurements from artifact
        logger.info("")
        logger.info("=" * 80)
        logger.info("Pulling Artifact from GitHub Container Registry")
        logger.info("=" * 80)
        
        pcr_measurement = pull_artifact_from_ghcr(ssh_client, args.artifact_ref)

        # Upload snapshot and register AMI
        logger.info("")
        logger.info("=" * 80)
        logger.info("Uploading Snapshot and Registering AMI")
        logger.info("=" * 80)
        
        architecture = "x86_64"
        snapshot_id = upload_snapshot(ssh_client, args.region)
        ami_name = f"attestable-ami-imported-{architecture}-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        ami_id = register_ami(ec2_client, snapshot_id, architecture, ami_name)

        # Cleanup and save results
        logger.info("")
        logger.info("=" * 80)
        logger.info("Cleanup and Save Results")
        logger.info("=" * 80)
        
        # Close SSH connection before destroying infrastructure
        if ssh_client:
            ssh_client.close()
            ssh_client = None
        
        # Save build result to file
        build_result = {
            "ami_id": ami_id,
            "snapshot_id": snapshot_id,
            "region": args.region,
            "build_timestamp": datetime.now(timezone.utc).isoformat(),
            "pcr_measurements": {
                "pcr4": pcr_measurement['Measurements']['PCR4'],
                "pcr7": pcr_measurement['Measurements']['PCR7'],
            }
        }

        with open(args.output_file, 'w') as f:
            json.dump(build_result, f, indent=2)
        
        return 0

    except Exception as e:
        logger.error("")
        logger.error("=" * 80)
        logger.error("AMI BUILD FAILED")
        logger.error("=" * 80)
        logger.error(f"Error: {e}")
        logger.error("=" * 80)
        return 1

    finally:
        # Cleanup infrastructure
        logger.warning("Cleaning up infrastructure...")
        try:
            cleanup_infrastructure(
                region=args.region,
                instance_type=args.instance_type,
                allowed_ssh_cidr=allowed_ssh_cidr,
                ssh_key_path=ssh_key_path
            )
        except Exception as cleanup_error:
            logger.error(f"Failed to cleanup infrastructure: {cleanup_error}")

if __name__ == '__main__':
    sys.exit(main())
