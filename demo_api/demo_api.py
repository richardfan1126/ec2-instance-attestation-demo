#!/usr/bin/env python3
"""
Demo remote attestation API Service

Simple HTTP API for generating NitroTPM attestation documents.
This service runs on the EC2 instance and provides endpoints for client
to retreive attestation document

WARNING: This is for demo purpose
In production, attestation document SHOULD NOT be accessible remotely without restriction
"""

import json
import logging
import subprocess
import sys
import tempfile
import os
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Optional, Dict, Any
import base64

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('/var/log/attestation-api.log')
    ]
)
logger = logging.getLogger(__name__)


class AttestationAPIHandler(BaseHTTPRequestHandler):
    """HTTP request handler for attestation API endpoints."""
    
    def log_message(self, format: str, *args) -> None:
        """Override to use our logger instead of stderr."""
        logger.info(f"{self.address_string()} - {format % args}")
    
    def send_json_response(self, status_code: int, data: Dict[str, Any]) -> None:
        """Send a JSON response."""
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode('utf-8'))
    
    def send_error_response(
        self, 
        status_code: int, 
        message: str,
        error_type: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Send an error response with detailed diagnostic information.
        
        Args:
            status_code: HTTP status code
            message: Human-readable error message
            error_type: Type of error (e.g., 'SubprocessError', 'ValidationError')
            details: Additional diagnostic information (command, exit_code, stdout, stderr, etc.)
        """
        response_data = {
            'status': 'error',
            'error': message
        }
        
        if error_type:
            response_data['error_type'] = error_type
        
        if details:
            response_data['details'] = details
        
        self.send_json_response(status_code, response_data)
    
    def do_GET(self) -> None:
        """Handle GET requests."""
        if self.path == '/health':
            self.handle_health()
        else:
            self.send_error_response(404, 'Not Found')
    
    def do_POST(self) -> None:
        """Handle POST requests."""
        if self.path == '/attest':
            self.handle_attest()
        else:
            self.send_error_response(404, 'Not Found')
    
    def do_OPTIONS(self) -> None:
        """Handle OPTIONS requests for CORS."""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
    
    def handle_health(self) -> None:
        """Handle health check endpoint."""
        logger.info("Health check requested")
        self.send_json_response(200, {
            'status': 'healthy',
            'service': 'attestation-api',
            'version': '1.0.0'
        })
    
    def handle_attest(self) -> None:
        """
        Handle attestation document generation endpoint.
        
        Accepts JSON payload with optional 'user_data' field.
        Generates attestation document using nitro-tpm-attest.
        """
        from datetime import datetime
        
        logger.info("Attestation request received")
        
        # Track context variables for error reporting
        content_length = None
        body = None
        request_data = None
        user_data = None
        
        try:
            # Read request body
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length > 0:
                body = self.rfile.read(content_length)
                try:
                    request_data = json.loads(body.decode('utf-8'))
                except json.JSONDecodeError as e:
                    logger.error(f"Invalid JSON in request: {e}")
                    self.send_error_response(
                        400, 
                        'Invalid JSON in request body',
                        error_type='JSONDecodeError',
                        details={
                            'exception_message': str(e),
                            'timestamp': datetime.utcnow().isoformat() + 'Z',
                            'context': {
                                'content_length': content_length,
                                'body_preview': body[:200].decode('utf-8', errors='replace') if body else None
                            }
                        }
                    )
                    return
            else:
                request_data = {}
            
            # Extract user data from request (optional)
            user_data = request_data.get('user_data')
            
            # Generate attestation document with detailed error handling
            result = self.generate_attestation_document(user_data)
            
            if result is None:
                # Error already logged and sent by generate_attestation_document
                return
            
            attestation_doc, error_details = result
            
            if attestation_doc is None:
                # Send detailed error response
                self.send_error_response(
                    500,
                    'Failed to generate attestation document',
                    error_type=error_details.get('error_type', 'UnknownError'),
                    details=error_details
                )
                return
            
            # Encode attestation document as base64
            attestation_doc_b64 = base64.b64encode(attestation_doc).decode('utf-8')
            
            # Send response
            response_data = {
                'status': 'success',
                'attestation_document': attestation_doc_b64
            }
            
            logger.info("Attestation document generated successfully")
            self.send_json_response(200, response_data)
        
        except UnicodeDecodeError as e:
            logger.error(f"Failed to decode request body: {e}", exc_info=True)
            self.send_error_response(
                400,
                'Failed to decode request body as UTF-8',
                error_type='UnicodeDecodeError',
                details={
                    'exception_message': str(e),
                    'timestamp': datetime.utcnow().isoformat() + 'Z',
                    'context': {
                        'content_length': content_length,
                        'encoding_error_position': e.start if hasattr(e, 'start') else None
                    }
                }
            )
        
        except ValueError as e:
            logger.error(f"Value error in attestation request: {e}", exc_info=True)
            self.send_error_response(
                400,
                'Invalid value in request',
                error_type='ValueError',
                details={
                    'exception_message': str(e),
                    'timestamp': datetime.utcnow().isoformat() + 'Z',
                    'context': {
                        'content_length': content_length,
                        'request_data_keys': list(request_data.keys()) if request_data else None,
                        'user_data_provided': user_data is not None
                    }
                }
            )
        
        except TypeError as e:
            logger.error(f"Type error in attestation request: {e}", exc_info=True)
            self.send_error_response(
                400,
                'Invalid type in request',
                error_type='TypeError',
                details={
                    'exception_message': str(e),
                    'timestamp': datetime.utcnow().isoformat() + 'Z',
                    'context': {
                        'content_length': content_length,
                        'request_data_type': type(request_data).__name__ if request_data is not None else None,
                        'user_data_type': type(user_data).__name__ if user_data is not None else None
                    }
                }
            )
        
        except OSError as e:
            logger.error(f"OS error in attestation request: {e}", exc_info=True)
            self.send_error_response(
                500,
                'Operating system error occurred',
                error_type='OSError',
                details={
                    'exception_message': str(e),
                    'timestamp': datetime.utcnow().isoformat() + 'Z',
                    'context': {
                        'errno': e.errno if hasattr(e, 'errno') else None,
                        'filename': e.filename if hasattr(e, 'filename') else None,
                        'user_data_provided': user_data is not None
                    }
                }
            )
        
        except MemoryError as e:
            logger.error(f"Memory error in attestation request: {e}", exc_info=True)
            self.send_error_response(
                500,
                'Insufficient memory to process request',
                error_type='MemoryError',
                details={
                    'exception_message': str(e),
                    'timestamp': datetime.utcnow().isoformat() + 'Z',
                    'context': {
                        'content_length': content_length,
                        'request_size_bytes': len(body) if body else 0
                    }
                }
            )
        
        except Exception as e:
            logger.error(f"Unexpected error handling attestation request: {e}", exc_info=True)
            self.send_error_response(
                500, 
                'Internal server error',
                error_type=type(e).__name__,
                details={
                    'exception_message': str(e),
                    'exception_type': type(e).__name__,
                    'timestamp': datetime.utcnow().isoformat() + 'Z',
                    'context': {
                        'endpoint': '/attest',
                        'method': 'POST',
                        'content_length': content_length,
                        'request_data_available': request_data is not None,
                        'user_data_provided': user_data is not None
                    }
                }
            )
    
    def generate_attestation_document(self, user_data: Optional[str] = None) -> Optional[tuple]:
        """
        Generate attestation document using nitro-tpm-attest.
        
        Args:
            user_data: Optional user data
        
        Returns:
            Tuple of (attestation_document, error_details) where:
            - attestation_document: bytes (CBOR format) or None on failure
            - error_details: dict with diagnostic information (only present on failure)
        """
        from datetime import datetime
        
        temp_userdata_file = None
        
        try:
            # If user data provided, save it to a temporary file
            if user_data:
                fd, temp_userdata_file = tempfile.mkstemp(suffix='.txt', prefix='userdata-')
                try:
                    with os.fdopen(fd, 'w') as f:
                        f.write(user_data)
                except Exception:
                    os.close(fd)
                    raise
                
                logger.info(f"User data saved to temporary file: {temp_userdata_file}")
            
            # Build nitro-tpm-attest command
            cmd = ['/usr/bin/nitro-tpm-attest']
            
            # If user data provided, pass it to the command
            if user_data:
                cmd.extend(['--user-data', temp_userdata_file])
            
            logger.info(f"Executing: {' '.join(cmd)}")
            
            # Execute nitro-tpm-attest (outputs to stdout)
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=30
            )
            
            if result.returncode != 0:
                logger.error(f"nitro-tpm-attest failed with exit code {result.returncode}")
                logger.error(f"stdout: {result.stdout}")
                logger.error(f"stderr: {result.stderr}")
                
                # Truncate stdout/stderr if too large (max 10KB each)
                max_output_size = 10240
                stdout_truncated = result.stdout[:max_output_size] if len(result.stdout) > max_output_size else result.stdout
                stderr_truncated = result.stderr[:max_output_size] if len(result.stderr) > max_output_size else result.stderr
                
                # Decode stderr for error message
                stderr_text = stderr_truncated.decode('utf-8', errors='replace') if isinstance(stderr_truncated, bytes) else stderr_truncated
                
                error_details = {
                    'error_type': 'SubprocessError',
                    'command': ' '.join(cmd),
                    'exit_code': result.returncode,
                    'stdout': stdout_truncated.decode('utf-8', errors='replace') if isinstance(stdout_truncated, bytes) else stdout_truncated,
                    'stderr': stderr_text,
                    'timestamp': datetime.utcnow().isoformat() + 'Z',
                    'context': {
                        'user_data_provided': user_data is not None,
                        'temp_userdata_file': temp_userdata_file
                    }
                }
                
                if len(result.stdout) > max_output_size:
                    error_details['stdout_truncated'] = True
                if len(result.stderr) > max_output_size:
                    error_details['stderr_truncated'] = True
                
                return (None, error_details)
            
            logger.info("nitro-tpm-attest executed successfully")
            
            # Attestation document is in stdout (binary CBOR format)
            attestation_doc = result.stdout
            
            logger.info(f"Attestation document size: {len(attestation_doc)} bytes")
            
            return (attestation_doc, None)
            
        except subprocess.TimeoutExpired as e:
            logger.error("nitro-tpm-attest timed out")
            error_details = {
                'error_type': 'TimeoutError',
                'command': ' '.join(cmd) if 'cmd' in locals() else 'unknown',
                'timeout_seconds': 30,
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'context': {
                    'user_data_provided': user_data is not None,
                    'temp_userdata_file': temp_userdata_file
                }
            }
            return (None, error_details)
            
        except Exception as e:
            logger.error(f"Error generating attestation document: {e}", exc_info=True)
            error_details = {
                'error_type': type(e).__name__,
                'exception_message': str(e),
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'context': {
                    'user_data_provided': user_data is not None,
                    'temp_userdata_file': temp_userdata_file
                }
            }
            return (None, error_details)
            
        finally:
            # Clean up temporary user data file
            if temp_userdata_file and os.path.exists(temp_userdata_file):
                try:
                    os.unlink(temp_userdata_file)
                except Exception as e:
                    logger.warning(f"Failed to remove temporary userdata file: {e}")


def run_server(port: int = 8080) -> None:
    """
    Run the HTTP server.
    
    Args:
        port: Port number to listen on (default: 8080)
    """
    server_address = ('', port)
    httpd = HTTPServer(server_address, AttestationAPIHandler)
    
    logger.info(f"Starting Attestation API server on port {port}")
    logger.info("Endpoints:")
    logger.info("  GET  /health - Health check")
    logger.info("  POST /attest - Generate attestation document")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Server error: {e}", exc_info=True)
    finally:
        httpd.server_close()
        logger.info("Server shut down")


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Attestation API Service')
    parser.add_argument(
        '--port',
        type=int,
        default=8080,
        help='Port to listen on (default: 8080)'
    )
    
    args = parser.parse_args()
    
    run_server(args.port)
