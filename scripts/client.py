#!/usr/bin/env python3
"""
A client script to interact with the demo instance API service

Retrieve the attestation document from the target instance,
and demostrate the verification process
"""

# AWS Nitro Enclaves Root Certificate Fingerprint (SHA-256)
# Source: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/nitrotpm-attestation-document-validate.html
AWS_NITRO_ROOT_CERT_FINGERPRINT = "64:1A:03:21:A3:E2:44:EF:E4:56:46:31:95:D6:06:31:7E:D7:CD:CC:3C:17:56:E0:98:93:F3:C6:8F:79:BB:5B"

import argparse
import base64
from dataclasses import dataclass
import json
import logging
from pathlib import Path
import sys
import time
from typing import Optional, Tuple

import requests
import cbor2

from OpenSSL import crypto

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.exceptions import InvalidSignature

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('client.log')
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class AttestationValidationResult:
    """Result of attestation document validation"""
    signature_valid: bool
    certificate_chain_valid: bool
    pcr4_match: bool
    pcr7_match: bool
    error_message: Optional[str] = None
    
    @property
    def is_valid(self) -> bool:
        """
        Overall validation status.
        
        Returns True only if all validations pass:
        - COSE signature is valid
        - Certificate chain is valid
        - PCR4 measurement matches reference
        - PCR7 measurement matches reference
        """
        return (
            self.signature_valid and 
            self.certificate_chain_valid and 
            self.pcr4_match and 
            self.pcr7_match
        )
    
    def display(self) -> None:
        """Display validation results in formatted output with visual indicators"""
        print("=" * 80)
        print("ATTESTATION VALIDATION SUMMARY")
        print("=" * 80)
        
        # Display each validation result with VALID/INVALID status
        status_signature = "VALID" if self.signature_valid else "INVALID"
        status_chain = "VALID" if self.certificate_chain_valid else "INVALID"
        status_pcr4 = "MATCH" if self.pcr4_match else "MISMATCH"
        status_pcr7 = "MATCH" if self.pcr7_match else "MISMATCH"
        
        # Use visual indicators (checkmark for valid, X for invalid)
        symbol_signature = "✓" if self.signature_valid else "✗"
        symbol_chain = "✓" if self.certificate_chain_valid else "✗"
        symbol_pcr4 = "✓" if self.pcr4_match else "✗"
        symbol_pcr7 = "✓" if self.pcr7_match else "✗"
        
        print(f"{symbol_signature} COSE Signature:      {status_signature}")
        print(f"{symbol_chain} Certificate Chain:   {status_chain}")
        print(f"{symbol_pcr4} PCR4 Measurement:    {status_pcr4}")
        print(f"{symbol_pcr7} PCR7 Measurement:    {status_pcr7}")
        print()
        
        # Display overall status
        if self.is_valid:
            print(f"✓ Overall Status:      ATTESTATION VERIFIED")
        else:
            print(f"✗ Overall Status:      ATTESTATION FAILED")
        
        # Include error message if validation fails
        if self.error_message:
            print()
            print(f"✗ Error: {self.error_message}")
        
        print("=" * 80)


@dataclass
class ParsedAttestationDocument:
    """Parsed representation of a NitroTPM attestation document"""
    
    # COSE envelope metadata
    cose_protected_headers: dict
    cose_unprotected_headers: dict
    cose_signature: bytes
    
    # Attestation document fields
    module_id: str
    timestamp: int
    digest_algorithm: str
    pcrs: dict  # PCR register number -> hex value
    certificate: bytes
    cabundle: list
    user_data: Optional[bytes] = None
    nonce: Optional[bytes] = None
    
    def format_timestamp(self) -> str:
        """Convert Unix timestamp to ISO 8601 format"""
        from datetime import datetime
        # NitroTPM timestamps are in milliseconds, convert to seconds
        timestamp_seconds = self.timestamp / 1000.0
        return datetime.fromtimestamp(timestamp_seconds).isoformat() + 'Z'
    
    def get_pcr_hex(self, pcr_num: int) -> str:
        """Get PCR value as hexadecimal string"""
        return self.pcrs.get(pcr_num, "Not present")
    
    def display(self) -> None:
        """Display attestation document in formatted, human-readable layout"""
        print("=" * 80)
        print("ATTESTATION DOCUMENT DETAILS")
        print("=" * 80)
        print()
        
        # COSE Envelope
        print("COSE Envelope:")
        print(f"  Structure Type: COSE_Sign1 (4-element array)")
        print(f"  Protected Headers: {self.cose_protected_headers}")
        print(f"  Unprotected Headers: {self.cose_unprotected_headers}")
        print(f"  Signature Length: {len(self.cose_signature)} bytes")
        print(f"  Signature (hex): {self.cose_signature.hex()[:64]}...")
        print()
        
        # Attestation Document Payload
        print("Attestation Document Payload:")
        print(f"  Module ID: {self.module_id}")
        print(f"  Timestamp: {self.format_timestamp()} (Unix: {self.timestamp})")
        print(f"  Digest Algorithm: {self.digest_algorithm}")
        print()
        
        # PCRs
        print("Platform Configuration Registers (PCRs):")
        for pcr_num in sorted(self.pcrs.keys()):
            pcr_value = self.pcrs[pcr_num]
            marker = " ← Used for attestation" if pcr_num in [4, 7] else ""
            print(f"  PCR {pcr_num}: {pcr_value}{marker}")
        print()
        
        # Certificate Chain
        print("Certificate Chain:")
        print(f"  Leaf Certificate Length: {len(self.certificate)} bytes")
        print(f"  CA Bundle Certificates: {len(self.cabundle)}")
        print()
        
        # Additional Fields
        print("Additional Fields:")
        print(f"  User Data: {self.user_data.hex() if self.user_data else 'null'}")
        print(f"  Nonce: {self.nonce.hex() if self.nonce else 'null'}")
        print()
        print("=" * 80)
    
    @classmethod
    def from_cbor_bytes(cls, attestation_document: bytes) -> 'ParsedAttestationDocument':
        """
        Parse CBOR-encoded COSE attestation document
        
        Args:
            attestation_document: Raw CBOR bytes from attestation API
            
        Returns:
            ParsedAttestationDocument instance
            
        Raises:
            ValueError: If document structure is invalid
        """
        # Decode COSE structure (4-element array)
        cose_structure = cbor2.loads(attestation_document)
        
        if not isinstance(cose_structure, list) or len(cose_structure) != 4:
            raise ValueError(f"Invalid COSE structure: expected 4-element list, got {type(cose_structure)}")
        
        # Extract COSE components
        protected_headers_bytes = cose_structure[0]
        unprotected_headers = cose_structure[1]
        payload_bytes = cose_structure[2]
        signature = cose_structure[3]
        
        # Decode protected headers
        protected_headers = cbor2.loads(protected_headers_bytes) if protected_headers_bytes else {}
        
        # Decode payload (the actual attestation document)
        payload = cbor2.loads(payload_bytes)
        
        # Extract PCRs and convert to hex strings
        pcrs_raw = payload.get('nitrotpm_pcrs', {})
        pcrs = {
            pcr_num: pcr_value.hex() if isinstance(pcr_value, bytes) else pcr_value
            for pcr_num, pcr_value in pcrs_raw.items()
        }
        
        return cls(
            cose_protected_headers=protected_headers,
            cose_unprotected_headers=unprotected_headers,
            cose_signature=signature,
            module_id=payload.get('module_id', 'Unknown'),
            timestamp=payload.get('timestamp', 0),
            digest_algorithm=payload.get('digest', 'Unknown'),
            pcrs=pcrs,
            certificate=payload.get('certificate', b''),
            cabundle=payload.get('cabundle', []),
            user_data=payload.get('user_data'),
            nonce=payload.get('nonce')
        )

def request_attestation_document(
    api_url: str,
    max_attempts: int = 5
) -> bytes:
    """
    Request attestation document from the HTTP API.
    Sends HTTP POST request to /attest endpoint.
    
    Args:
        api_url: Base URL of the attestation API
        max_attempts: Maximum number of retry attempts
    
    Returns:
        Attestation document as bytes (CBOR format)
    
    Raises:
        RuntimeError: If all retry attempts fail
    """
    logger.info(f"Requesting attestation document from {api_url}...")
    
    
    endpoint = f"{api_url}/attest"
    payload = {}
    
    for attempt in range(1, max_attempts + 1):
        try:
            logger.info(f"Attempt {attempt}/{max_attempts}: Sending POST request to {endpoint}")
            
            response = requests.post(
                endpoint,
                json=payload,
                timeout=30
            )
            
            # Check HTTP status
            if response.status_code != 200:
                # Try to parse error response for detailed information
                error_message = _parse_error_response(response)
                logger.warning(f"HTTP {response.status_code}: {error_message}")
                
                if attempt < max_attempts:
                    delay = 2 ** attempt  # Exponential backoff
                    logger.info(f"Retrying in {delay} seconds...")
                    time.sleep(delay)
                    continue
                else:
                    raise RuntimeError(f"HTTP {response.status_code}: {error_message}")
            
            # Parse JSON response
            try:
                response_data = response.json()
            except json.JSONDecodeError as e:
                raise RuntimeError(f"Failed to parse JSON response: {e}")
            
            # Check for error status in response
            if response_data.get('status') == 'error':
                error_message = _format_detailed_error(response_data)
                raise RuntimeError(f"API returned error: {error_message}")
            
            # Extract attestation document
            if 'attestation_document' not in response_data:
                raise RuntimeError("Response missing 'attestation_document' field")
            
            attestation_document_b64 = response_data['attestation_document']
            
            # Decode from base64
            try:
                attestation_document = base64.b64decode(attestation_document_b64)
            except Exception as e:
                raise RuntimeError(f"Failed to decode base64 attestation document: {e}")
            
            logger.info(f"✓ Attestation document retrieved successfully ({len(attestation_document)} bytes)")
            
            return attestation_document
            
        except requests.exceptions.ConnectionError as e:
            logger.warning(f"Connection failed: {e}")
            if attempt < max_attempts:
                delay = 2 ** attempt  # Exponential backoff
                logger.info(f"Retrying in {delay} seconds...")
                time.sleep(delay)
            else:
                raise RuntimeError(f"Failed to connect after {max_attempts} attempts: {e}")
        
        except requests.exceptions.Timeout as e:
            logger.warning(f"Request timed out: {e}")
            if attempt < max_attempts:
                delay = 2 ** attempt  # Exponential backoff
                logger.info(f"Retrying in {delay} seconds...")
                time.sleep(delay)
            else:
                raise RuntimeError(f"Request timed out after {max_attempts} attempts: {e}")
        
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {e}")
            raise RuntimeError(f"HTTP request failed: {e}")
    
    raise RuntimeError(f"Failed to retrieve attestation document after {max_attempts} attempts")

def _parse_error_response(response: requests.Response) -> str:
    """
    Parse error response from the attestation API.
    Extract detailed error information from the API response.
    
    Args:
        response: HTTP response object
    
    Returns:
        Formatted error message string
    """
    try:
        error_data = response.json()
        return _format_detailed_error(error_data)
    except (json.JSONDecodeError, ValueError):
        # Fall back to raw text if JSON parsing fails
        return response.text


def _format_detailed_error(error_data: dict) -> str:
    """
    Format detailed error information from API response for user-friendly display.
    
    Extracts and formats error_type, command, exit_code, stdout, stderr,
    and contextual information from the error response.
    
    Args:
        error_data: Error response data from API
    
    Returns:
        Formatted error message string
    """
    error_message = error_data.get('error', 'Unknown error')
    error_type = error_data.get('error_type', 'Unknown')
    details = error_data.get('details', {})
    
    # Build formatted error message
    lines = [
        f"\n{'=' * 80}",
        "ATTESTATION API ERROR",
        f"{'=' * 80}",
        f"Error: {error_message}",
        f"Type: {error_type}"
    ]
    
    # Add timestamp if available
    if 'timestamp' in details:
        lines.append(f"Timestamp: {details['timestamp']}")
    
    # Add subprocess error details
    if 'command' in details:
        lines.extend([
            f"\nCommand Executed:",
            f"  {details['command']}"
        ])
    
    if 'exit_code' in details:
        lines.append(f"Exit Code: {details['exit_code']}")
    
    if 'stdout' in details and details['stdout']:
        stdout = details['stdout']
        if len(stdout) > 500:
            stdout = stdout[:500] + "... (truncated)"
        lines.extend([
            f"\nStandard Output:",
            f"  {stdout}"
        ])
    
    if 'stderr' in details and details['stderr']:
        stderr = details['stderr']
        if len(stderr) > 500:
            stderr = stderr[:500] + "... (truncated)"
        lines.extend([
            f"\nStandard Error:",
            f"  {stderr}"
        ])
    
    # Add context information
    if 'context' in details:
        context = details['context']
        lines.append(f"\nContext:")
        for key, value in context.items():
            lines.append(f"  {key}: {value}")
    
    lines.append(f"{'=' * 80}\n")
    
    # Log the detailed error
    formatted_error = "\n".join(lines)
    logger.error(formatted_error)
    
    # Return a concise summary for the exception message
    summary = f"{error_message} (Type: {error_type})"
    if 'exit_code' in details:
        summary += f" [Exit Code: {details['exit_code']}]"
    
    return summary

def compare_pcr_measurements(
    attestation_document: bytes,
    reference_measurements: dict
) -> Tuple[bool, bool]:
    """
    Compare PCR measurements from attestation document with reference values.
    
    Parses the CBOR-encoded attestation document and extracts PCR4 and PCR7
    measurements, then compares them with the reference measurements from
    the AMI build process.
    
    Args:
        attestation_document: CBOR-encoded attestation document
        reference_measurements: Reference PCR measurements from AMI build
    
    Returns:
        Tuple of (pcr4_match, pcr7_match)
    """
    logger.info("Comparing PCR measurements...")
    
    try:
        # Decode COSE structure (CBOR list: [protected, unprotected, payload, signature])
        cose_structure = cbor2.loads(attestation_document)
        
        if not isinstance(cose_structure, list) or len(cose_structure) != 4:
            logger.warning("Attestation document is not a valid COSE structure")
            return False, False
        
        # Extract the payload (the actual attestation document)
        payload = cose_structure[2]
        attestation_data = cbor2.loads(payload)
        
        # Extract PCR measurements (NitroTPM uses 'nitrotpm_pcrs')
        if 'nitrotpm_pcrs' not in attestation_data:
            logger.warning("Attestation document missing 'nitrotpm_pcrs' field")
            return False, False
        
        pcrs = attestation_data['nitrotpm_pcrs']
        
        # Get PCR4 and PCR7 values
        pcr4_actual = pcrs.get(4)
        pcr7_actual = pcrs.get(7)
        
        if not pcr4_actual or not pcr7_actual:
            logger.warning("Attestation document missing PCR4 or PCR7")
            return False, False
        
        # Convert bytes to hex string for comparison
        if isinstance(pcr4_actual, bytes):
            pcr4_actual = pcr4_actual.hex()
        if isinstance(pcr7_actual, bytes):
            pcr7_actual = pcr7_actual.hex()
        
        # Compare with reference measurements (case-insensitive)
        pcr4_match = pcr4_actual.lower() == reference_measurements['pcr4'].lower()
        pcr7_match = pcr7_actual.lower() == reference_measurements['pcr7'].lower()
        
        logger.info(f"PCR4 Comparison:")
        logger.info(f"  Reference: {reference_measurements['pcr4'][:32]}...{reference_measurements['pcr4'][-32:]}")
        logger.info(f"  Actual:    {pcr4_actual[:32]}...{pcr4_actual[-32:]}")
        logger.info(f"  Match:     {'YES' if pcr4_match else 'NO'}")
        
        logger.info(f"PCR7 Comparison:")
        logger.info(f"  Reference: {reference_measurements['pcr7'][:32]}...{reference_measurements['pcr7'][-32:]}")
        logger.info(f"  Actual:    {pcr7_actual[:32]}...{pcr7_actual[-32:]}")
        logger.info(f"  Match:     {'YES' if pcr7_match else 'NO'}")
        
        return pcr4_match, pcr7_match
        
    except Exception as e:
        logger.error(f"Failed to parse attestation document: {e}")
        return False, False

def verify_cose_signature(attestation_document: bytes, parsed_doc: ParsedAttestationDocument) -> bool:
    """
    Verify the COSE signature of the attestation document.
    
    Verifies that the attestation document has not been tampered with by
    validating the COSE_Sign1 signature using the certificate from the
    attestation document.
    
    Args:
        attestation_document: Raw CBOR-encoded COSE attestation document
        parsed_doc: Parsed attestation document containing certificate
    
    Returns:
        True if signature is valid, False otherwise
    """
    logger.info("Verifying COSE signature...")
    
    try:
        # Parse COSE structure to extract components
        cose_structure = cbor2.loads(attestation_document)
        
        if not isinstance(cose_structure, list) or len(cose_structure) != 4:
            logger.error(f"Invalid COSE structure: expected 4-element list, got {type(cose_structure)}")
            return False
        
        protected_headers_bytes = cose_structure[0]
        unprotected_headers = cose_structure[1]
        payload_bytes = cose_structure[2]
        signature = cose_structure[3]
        
        logger.info(f"✓ COSE structure parsed successfully")
        logger.info(f"  Protected headers length: {len(protected_headers_bytes)} bytes")
        logger.info(f"  Payload length: {len(payload_bytes)} bytes")
        logger.info(f"  Signature length: {len(signature)} bytes")
        
        # Decode protected headers to get algorithm
        if protected_headers_bytes:
            protected_headers = cbor2.loads(protected_headers_bytes)
            algorithm = protected_headers.get(1)  # Algorithm is key 1 in COSE
            logger.info(f"  Signature algorithm: {algorithm} (ES384 = -35)")
        else:
            logger.warning("  No protected headers found")
            algorithm = None
        
        # Load the leaf certificate from the attestation document
        try:
            certificate = x509.load_der_x509_certificate(parsed_doc.certificate, default_backend())
            logger.info(f"✓ Leaf certificate loaded successfully")
            logger.info(f"  Subject: {certificate.subject.rfc4514_string()}")
            logger.info(f"  Issuer: {certificate.issuer.rfc4514_string()}")
        except Exception as e:
            logger.error(f"Failed to parse certificate: {e}")
            return False
        
        # Extract the public key from the certificate
        public_key = certificate.public_key()
        
        # Verify the public key is an EC key (ECDSA)
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            logger.error(f"Unsupported public key type: {type(public_key)}")
            logger.error("Expected EC (Elliptic Curve) public key for ES384 signature")
            return False
        
        logger.info(f"✓ Public key extracted from certificate")
        logger.info(f"  Key type: EC (Elliptic Curve)")
        logger.info(f"  Curve: {public_key.curve.name}")
        
        # Construct the Sig_structure for COSE_Sign1
        # Sig_structure = [
        #     context = "Signature1",
        #     body_protected = protected_headers_bytes,
        #     external_aad = b"",
        #     payload = payload_bytes
        # ]
        sig_structure = [
            "Signature1",
            protected_headers_bytes,
            b"",  # external_aad (empty for attestation documents)
            payload_bytes
        ]
        
        # Encode Sig_structure as CBOR
        sig_structure_bytes = cbor2.dumps(sig_structure)
        
        logger.info(f"✓ Sig_structure constructed ({len(sig_structure_bytes)} bytes)")
        
        # Verify the signature using the public key
        # ES384 uses ECDSA with SHA-384
        if algorithm == -35:  # ES384
            hash_algorithm = hashes.SHA384()
            logger.info(f"  Using ECDSA with SHA-384 for verification")
        elif algorithm == -7:  # ES256
            hash_algorithm = hashes.SHA256()
            logger.info(f"  Using ECDSA with SHA-256 for verification")
        else:
            logger.warning(f"  Unknown algorithm {algorithm}, defaulting to SHA-384")
            hash_algorithm = hashes.SHA384()
        
        # Convert raw ECDSA signature to DER format
        # AWS Nitro uses raw format (r || s), but cryptography library expects DER
        # For ES384: signature is 96 bytes (48 bytes r + 48 bytes s)
        # For ES256: signature is 64 bytes (32 bytes r + 32 bytes s)
        try:
            if len(signature) == 96:  # ES384
                r = int.from_bytes(signature[:48], byteorder='big')
                s = int.from_bytes(signature[48:], byteorder='big')
            elif len(signature) == 64:  # ES256
                r = int.from_bytes(signature[:32], byteorder='big')
                s = int.from_bytes(signature[32:], byteorder='big')
            else:
                logger.error(f"Unexpected signature length: {len(signature)} bytes")
                return False
            
            # Encode as DER
            der_signature = encode_dss_signature(r, s)
            logger.info(f"  Converted raw signature to DER format")
            
        except Exception as e:
            logger.error(f"Failed to convert signature format: {e}")
            return False
        
        try:
            public_key.verify(
                der_signature,
                sig_structure_bytes,
                ec.ECDSA(hash_algorithm)
            )
            logger.info("✓ COSE signature is VALID")
            logger.info("  → Attestation document has not been tampered with")
            return True
            
        except InvalidSignature:
            logger.error("✗ COSE signature is INVALID")
            logger.error("  → Attestation document may have been tampered with")
            return False
        
    except Exception as e:
        logger.error(f"Error during signature verification: {e}", exc_info=True)
        return False

def validate_certificate_chain(certificate: bytes, cabundle: list) -> bool:
    """
    Validate the certificate chain against AWS Nitro root certificates.
    
    Uses OpenSSL.crypto X509StoreContext to validate the entire certificate chain,
    including signature verification and validity period checks. Compares the root
    certificate against known AWS Nitro root certificate fingerprints.
    
    Args:
        certificate: Leaf certificate in DER format (bytes)
        cabundle: List of CA bundle certificates in DER format (bytes)
    
    Returns:
        True if chain is valid and root matches AWS Nitro root, False otherwise
    """
    logger.info("Validating certificate chain...")
    
    try:
        # Parse the leaf certificate
        try:
            leaf_cert = crypto.load_certificate(crypto.FILETYPE_ASN1, certificate)
            logger.info(f"✓ Leaf certificate loaded successfully")
            logger.info(f"  Subject: {leaf_cert.get_subject().CN}")
            logger.info(f"  Issuer: {leaf_cert.get_issuer().CN}")
            
            # Get validity period
            not_before = leaf_cert.get_notBefore().decode('utf-8')
            not_after = leaf_cert.get_notAfter().decode('utf-8')
            logger.info(f"  Valid From: {not_before}")
            logger.info(f"  Valid To: {not_after}")
            
        except Exception as e:
            logger.error(f"Failed to parse leaf certificate: {e}")
            return False
        
        # Parse all CA bundle certificates
        ca_certs = []
        for i, ca_cert_der in enumerate(cabundle):
            try:
                ca_cert = crypto.load_certificate(crypto.FILETYPE_ASN1, ca_cert_der)
                ca_certs.append(ca_cert)
                
                logger.info(f"✓ CA Certificate {i} loaded successfully")
                logger.info(f"  Subject: {ca_cert.get_subject().CN}")
                logger.info(f"  Issuer: {ca_cert.get_issuer().CN}")
                
                # Get validity period
                not_before = ca_cert.get_notBefore().decode('utf-8')
                not_after = ca_cert.get_notAfter().decode('utf-8')
                logger.info(f"  Valid From: {not_before}")
                logger.info(f"  Valid To: {not_after}")
                
            except Exception as e:
                logger.error(f"Failed to parse CA certificate {i}: {e}")
                return False
        
        if not ca_certs:
            logger.error("CA bundle is empty - cannot validate certificate chain")
            return False
        
        # Build an X509Store containing the CA bundle certificates
        # The CA bundle should be ordered: [ROOT, INTERMEDIATE_1, ..., INTERMEDIATE_N]
        # We add all certificates to the store as trusted certificates
        store = crypto.X509Store()
        
        for ca_cert in ca_certs:
            store.add_cert(ca_cert)
        
        logger.info(f"✓ X509Store created with {len(ca_certs)} CA certificates")
        
        # Create an X509StoreContext with the store and leaf certificate
        # This will validate the entire chain automatically
        store_ctx = crypto.X509StoreContext(store, leaf_cert)
        
        # Verify the certificate chain
        # This automatically:
        # - Verifies each certificate is signed by the next one in the chain
        # - Checks that the current time is within each certificate's validity period
        # - Validates the chain up to a trusted root certificate
        try:
            store_ctx.verify_certificate()
            logger.info("✓ Certificate chain validation successful")
            logger.info("  → All certificates are properly signed")
            logger.info("  → All certificates are within validity period")
            
        except crypto.X509StoreContextError as e:
            logger.error(f"✗ Certificate chain validation failed: {e}")
            logger.error("  → Chain may be incomplete, expired, or have invalid signatures")
            return False
        
        # Verify the root certificate matches known AWS Nitro root certificate
        # The root certificate should be the first certificate in the CA bundle
        root_cert = ca_certs[0]
        
        # Calculate SHA-256 fingerprint of the root certificate
        root_cert_digest = root_cert.digest("sha256").decode('utf-8')
        
        logger.info(f"Root certificate fingerprint (SHA-256):")
        logger.info(f"  Actual:   {root_cert_digest}")
        logger.info(f"  Expected: {AWS_NITRO_ROOT_CERT_FINGERPRINT}")
        
        if root_cert_digest.upper() == AWS_NITRO_ROOT_CERT_FINGERPRINT.upper():
            logger.info("✓ Root certificate matches known AWS Nitro root certificate")
            logger.info("  → Attestation came from genuine AWS Nitro instance")
            return True
        else:
            logger.error("✗ Root certificate does NOT match known AWS Nitro root certificate")
            logger.error("  → Attestation may not be from a genuine AWS Nitro instance")
            return False
        
    except Exception as e:
        logger.error(f"Error during certificate chain validation: {e}", exc_info=True)
        return False

def validate_attestation_document(
    attestation_document: bytes,
    reference_measurements: dict
) -> AttestationValidationResult:
    """
    Orchestrate the complete attestation document validation process.
    
    Performs comprehensive validation of the attestation document including:
    1. Parsing the CBOR-encoded COSE structure
    2. Verifying the COSE signature
    3. Validating the certificate chain against AWS Nitro root certificates
    4. Comparing PCR4 and PCR7 measurements against reference values
    
    Args:
        attestation_document: Raw CBOR-encoded COSE attestation document
        reference_measurements: Reference PCR measurements from AMI build
    
    Returns:
        AttestationValidationResult with all validation results
    """
    logger.info("=" * 80)
    logger.info("Starting Attestation Document Validation")
    logger.info("=" * 80)
    
    # Initialize validation results
    signature_valid = False
    certificate_chain_valid = False
    pcr4_match = False
    pcr7_match = False
    error_message = None
    
    try:
        # Parse attestation document
        logger.info("")
        logger.info("Parsing Attestation Document")
        logger.info("-" * 80)
        
        try:
            parsed_doc = ParsedAttestationDocument.from_cbor_bytes(attestation_document)
            logger.info("✓ Attestation document parsed successfully")
            logger.info(f"  Module ID: {parsed_doc.module_id}")
            logger.info(f"  Timestamp: {parsed_doc.format_timestamp()}")
            logger.info(f"  PCRs present: {len(parsed_doc.pcrs)}")
            
        except ValueError as e:
            error_message = f"Failed to parse attestation document: {e}"
            logger.error(f"✗ {error_message}")
            return AttestationValidationResult(
                signature_valid=False,
                certificate_chain_valid=False,
                pcr4_match=False,
                pcr7_match=False,
                error_message=error_message
            )
        except Exception as e:
            error_message = f"Unexpected error parsing attestation document: {e}"
            logger.error(f"✗ {error_message}", exc_info=True)
            return AttestationValidationResult(
                signature_valid=False,
                certificate_chain_valid=False,
                pcr4_match=False,
                pcr7_match=False,
                error_message=error_message
            )
        
        # Verify COSE signature
        logger.info("")
        logger.info("Verifying COSE Signature")
        logger.info("-" * 80)
        
        try:
            signature_valid = verify_cose_signature(attestation_document, parsed_doc)
            
            if signature_valid:
                logger.info("✓ COSE signature verification: PASSED")
            else:
                logger.error("✗ COSE signature verification: FAILED")
                error_message = "COSE signature verification failed"
                
        except Exception as e:
            error_message = f"Error during COSE signature verification: {e}"
            logger.error(f"✗ {error_message}", exc_info=True)
            signature_valid = False
        
        # Validate certificate chain
        logger.info("")
        logger.info("Validating Certificate Chain")
        logger.info("-" * 80)
        
        try:
            certificate_chain_valid = validate_certificate_chain(
                parsed_doc.certificate,
                parsed_doc.cabundle
            )
            
            if certificate_chain_valid:
                logger.info("✓ Certificate chain validation: PASSED")
            else:
                logger.error("✗ Certificate chain validation: FAILED")
                if not error_message:
                    error_message = "Certificate chain validation failed"
                    
        except Exception as e:
            error_msg = f"Error during certificate chain validation: {e}"
            logger.error(f"✗ {error_msg}", exc_info=True)
            certificate_chain_valid = False
            if not error_message:
                error_message = error_msg
        
        # Compare PCR measurements
        logger.info("")
        logger.info("Comparing PCR Measurements")
        logger.info("-" * 80)
        
        try:
            pcr4_match, pcr7_match = compare_pcr_measurements(
                attestation_document,
                reference_measurements
            )
            
            if pcr4_match and pcr7_match:
                logger.info("✓ PCR measurement comparison: PASSED")
            else:
                logger.error("✗ PCR measurement comparison: FAILED")
                if not pcr4_match:
                    logger.error("  PCR4 does not match reference value")
                if not pcr7_match:
                    logger.error("  PCR7 does not match reference value")
                if not error_message:
                    error_message = "PCR measurements do not match reference values"
                    
        except Exception as e:
            error_msg = f"Error during PCR comparison: {e}"
            logger.error(f"✗ {error_msg}", exc_info=True)
            pcr4_match = False
            pcr7_match = False
            if not error_message:
                error_message = error_msg
        
        # Create and return validation result
        validation_result = AttestationValidationResult(
            signature_valid=signature_valid,
            certificate_chain_valid=certificate_chain_valid,
            pcr4_match=pcr4_match,
            pcr7_match=pcr7_match,
            error_message=error_message
        )
        
        logger.info("")
        logger.info("=" * 80)
        logger.info("Attestation Document Validation Complete")
        logger.info("=" * 80)
        logger.info(f"Overall Status: {'VALID' if validation_result.is_valid else 'INVALID'}")
        
        return validation_result
        
    except Exception as e:
        # Catch-all for any unexpected errors
        error_message = f"Unexpected error during validation: {e}"
        logger.error(f"✗ {error_message}", exc_info=True)
        
        return AttestationValidationResult(
            signature_valid=signature_valid,
            certificate_chain_valid=certificate_chain_valid,
            pcr4_match=pcr4_match,
            pcr7_match=pcr7_match,
            error_message=error_message
        )

def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description='Demonstrate EC2 instance attestation'
    )
    
    parser.add_argument(
        '--infrastructure-state',
        type=str,
        default='infrastructure_state.json',
        help='Path to infrastructure state JSON file'
    )
    
    parser.add_argument(
        '--ami-build-result',
        type=str,
        default='ami_build_result.json',
        help='Path to AMI build result JSON file'
    )
    
    parser.add_argument(
        '--output-file',
        type=str,
        default='attestation_result.json',
        help='Output file for attestation result (default: attestation_result.json)'
    )
    
    parser.add_argument(
        '--attestation-document-file',
        type=str,
        default='attestation_document.cbor',
        help='File to save attestation document (default: attestation_document.cbor)'
    )
    
    return parser.parse_args()

def main() -> int:
    """Main entry point."""
    args = parse_arguments()
    
    logger.info("=" * 80)
    logger.info("Starting Attestation Demonstration")
    logger.info("=" * 80)
    logger.info(f"Infrastructure State: {args.infrastructure_state}")
    logger.info(f"AMI Build Result: {args.ami_build_result}")
    logger.info(f"Output File: {args.output_file}")
    
    try:
        # Load infrastructure state and AMI build result
        logger.info("")
        logger.info("=" * 80)
        logger.info("Loading Configuration")
        logger.info("=" * 80)
        
        if not Path(args.infrastructure_state).exists():
            raise FileNotFoundError(f"Infrastructure state file not found: {args.infrastructure_state}")
        
        if not Path(args.ami_build_result).exists():
            raise FileNotFoundError(f"AMI build result file not found: {args.ami_build_result}")
        
        try:
            with open(args.infrastructure_state, "r") as f:
                infrastructure_state = json.loads(f.read())
        except Exception as e:
            logger.error("Failed to read infrastructure state file")
            raise RuntimeError(f"Failed to read infrastructure state file: {e}")
        
        try:
            with open(args.ami_build_result, "r") as f:
                ami_build_result = json.loads(f.read())
        except Exception as e:
            logger.error("Failed to read AMI build result file")
            raise RuntimeError(f"Failed to read AMI build result file: {e}")
        
        logger.info(f"Instance ID: {infrastructure_state['instance_id']}")
        logger.info(f"Instance Public IP: {infrastructure_state['instance_public_ip']}")
        logger.info(f"Attestation API URL: {infrastructure_state['attestation_api_url']}")
        logger.info(f"Reference PCR4: {ami_build_result['pcr_measurements']['pcr4'][:32]}...{ami_build_result['pcr_measurements']['pcr4'][-32:]}")
        logger.info(f"Reference PCR7: {ami_build_result['pcr_measurements']['pcr7'][:32]}...{ami_build_result['pcr_measurements']['pcr7'][-32:]}")
        
        # Request attestation document via HTTP API
        logger.info("")
        logger.info("=" * 80)
        logger.info("Requesting Attestation Document")
        logger.info("=" * 80)
        
        attestation_document = request_attestation_document(
            infrastructure_state['attestation_api_url']
        )
        
        # Save attestation document to file
        with open(args.attestation_document_file, 'wb') as f:
            f.write(attestation_document)
        logger.info(f"Attestation document saved to: {args.attestation_document_file}")
        
        # Parse and display attestation document
        logger.info("")
        logger.info("=" * 80)
        logger.info("Parsing and Displaying Attestation Document")
        logger.info("=" * 80)
        
        try:
            parsed_doc = ParsedAttestationDocument.from_cbor_bytes(attestation_document)
            parsed_doc.display()
        except ValueError as e:
            logger.warning(f"Failed to parse attestation document: {e}")
            logger.warning("Displaying raw attestation document (hex):")
            logger.warning(f"  {attestation_document.hex()[:200]}... ({len(attestation_document)} bytes total)")
        except Exception as e:
            logger.error(f"Error parsing attestation document: {e}")
            logger.error("Displaying raw attestation document (hex):")
            logger.error(f"  {attestation_document.hex()[:200]}... ({len(attestation_document)} bytes total)")
        
        # Validate attestation document
        logger.info("")
        logger.info("=" * 80)
        logger.info("Validating Attestation Document")
        logger.info("=" * 80)
        
        validation_result = validate_attestation_document(
            attestation_document,
            ami_build_result['pcr_measurements']
        )
        
        # Display validation summary
        validation_result.display()
        
        # Check if validation passed
        if not validation_result.is_valid:
            logger.error("")
            logger.error("=" * 80)
            logger.error("ATTESTATION VALIDATION FAILED")
            logger.error("=" * 80)
            logger.error("Cannot proceed with KMS encryption/decryption")
            logger.error("The attestation document did not pass validation checks")
            logger.error("=" * 80)
            
            return 1
        
        logger.info("")
        logger.info("✓ Attestation validation passed")
        
        return 0
        
    except Exception as e:
        logger.error("")
        logger.error("=" * 80)
        logger.error("ATTESTATION DEMONSTRATION FAILED")
        logger.error("=" * 80)
        logger.error(f"Error: {e}")
        logger.error("=" * 80)
        
        return 1

if __name__ == '__main__':
    sys.exit(main())
