# EC2 NitroTPM Attestation Demo

Demonstrates AWS EC2 instance attestation using NitroTPM and Attestable AMIs.

This project demonstrate:
1. Building an [Attestable AMI](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/attestable-ami.html)
1. Verifying the image is built by the expected build pipeline
1. Requesting [attestation document](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/attestation-get-doc.html) from attestable EC2 instance
1. Verifying the attestation document

## Pre-requisite

To run this project, you need:
1. Python
1. [uv](https://github.com/astral-sh/uv)
1. [Terraform](https://developer.hashicorp.com/terraform/install)
1. An AWS account
1. AWS cli with [access configured](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-authentication.html)

## tl;dr

If you don't want to read through the document and just want to spin up something to see what's happening.

Just make sure you meet the pre-requisite, then run the following commands:

```bash
uv sync
uv run python scripts/build-ami.py \
    --artifact-ref ghcr.io/richardfan1126/ec2-instance-attestation-demo:main-20251217-075953
uv run python scripts/deploy.py
uv run python scripts/client.py
```

## Deployment

This project has a 3-stage deployment procedure

### Building raw disk image in GitHub Actions

The [Build Attestable Image](.github/workflows/build-attestable-image.yml) workflow build and attest a raw disk image on main branch push

This is done automatically on GitHub Actions, **no manual step needed**.

The workflow do the following:
1. Build a builder container image based on Amazon Linux 2023, with necessary tools (e.g. [KIWI NG](https://osinside.github.io/kiwi/overview.html), [aws-nitro-tpm-tools](https://github.com/aws/NitroTPM-Tools))
1. Run the build script based on a modified image description from [AL2023 attestable-image](https://github.com/amazonlinux/kiwi-image-descriptions-examples/tree/main/kiwi-image-descriptions-examples/al2023/attestable-image-example), with the following modification:
   * Add the [demo API service](demo_api) into the image
   * Minor changes to adapt image building inside container
1. Get the [PCR measurement](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/create-pcr-compute.html) of the image
1. Push the raw image file and the PCR measurement into GitHub Container Registry using [oras](https://oras.land/)
1. Perform [GitHub attestation](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations) against the pushed artifact

### Building AMI from raw disk image

Run the following command to build AMI from raw disk image available in GitHub Container Registry

```bash
uv sync
uv run python scripts/build-ami.py --artifact-ref <artifact-ref>
```

`<artifact-ref>` is the path of artifact pushed by the **Build Attestable Image** workflow. You can find it from the GitHub Actions run summary

Or if you don't have one, use `ghcr.io/richardfan1126/ec2-instance-attestation-demo:main-20251217-075953`, which is built by [this GitHub Actions run](https://github.com/richardfan1126/ec2-instance-attestation-demo/actions/runs/20295702089)

```bash
uv sync
uv run python scripts/build-ami.py --artifact-ref ghcr.io/richardfan1126/ec2-instance-attestation-demo:main-20251217-075953
```

This script will do the following:
1. Create an EC2 instance with SSH access, using Terraform
1. Through SSH, instruct the instance to:
   1. Pull the artifact from GitHub Container Registry
   1. Validate the artifact against GitHub Attestation
   1. Extract the raw image's PCR measurement
   1. Upload the raw image as Amazon EBS snapshot, using coldsnap
   1. Register an Attestable AMI from the EBS snapshot
1. Destroy the EC2 instance
1. Save the AMI information into `ami_build_result.json`

### Deploy an EC2 instance from the Attestable AMI

Run the following command to deploy an EC2 instance from the Attestable AMI

```bash
uv sync
uv run python scripts/deploy.py
```

This script will do the following:
1. Create an EC2 instance from the Attestable AMI, using Terraform
1. Save the instance info (e.g. public IP address), into `infrastructure_state.json`

## Using the client

After the EC2 instance is deployed, run the following script to run the demo client:

```bash
uv sync
uv run python scripts/client.py
```

This script will do the following:
1. Generate a random nonce (used to proof authenticity)
1. Send API request to the EC2 instance to request an NitroTPM attestation document
1. Validate the attestation document

The client will print out the decoded content of the attestation document as well as the validation step. So you can learn how attestation document works on Attestable AMI.

The raw attestation document is also saved in `attestation_document.cbor`

## Cleanup

Run the following script to cleanup resources

```bash
uv sync
uv run python scripts/cleanup.py
```
