"""Extract and analyze SSL/TLS certificate chain from remote servers."""

from __future__ import annotations

import socket
import ssl
import subprocess
from datetime import datetime
from typing import Dict, List, Optional, Tuple

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509.oid import ExtensionOID, NameOID
except ImportError:
    x509 = None
    default_backend = None


def format_certificate_subject(cert) -> str:
    """Extract subject name from certificate."""
    try:
        subject = cert.subject
        return subject.rfc4514_string()
    except Exception:
        return "Unknown Subject"


def format_certificate_issuer(cert) -> str:
    """Extract issuer name from certificate."""
    try:
        issuer = cert.issuer
        return issuer.rfc4514_string()
    except Exception:
        return "Unknown Issuer"


def extract_certificate_info(cert_der: bytes, chain_index: int = 0) -> Dict[str, object]:
    """Extract detailed information from a certificate."""
    if not x509:
        return {
            "index": chain_index,
            "error": "cryptography library not available"
        }
    
    try:
        cert = x509.load_der_x509_certificate(cert_der, default_backend())
        
        # Subject Alternative Names
        san_list = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            for name in san_ext.value:
                if isinstance(name, x509.DNSName):
                    san_list.append(name.value)
                elif isinstance(name, x509.IPAddress):
                    san_list.append(str(name.value))
        except x509.ExtensionNotFound:
            pass
        
        # Certificate usage
        key_usage = []
        try:
            ku_ext = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
            ku = ku_ext.value
            if ku.digital_signature:
                key_usage.append("Digital Signature")
            if ku.key_encipherment:
                key_usage.append("Key Encipherment")
            if ku.content_commitment:
                key_usage.append("Content Commitment")
            if ku.data_encipherment:
                key_usage.append("Data Encipherment")
            if ku.key_agreement:
                key_usage.append("Key Agreement")
            if ku.key_cert_sign:
                key_usage.append("Certificate Sign")
            if ku.crl_sign:
                key_usage.append("CRL Sign")
        except x509.ExtensionNotFound:
            pass
        
        # Extended Key Usage
        extended_key_usage = []
        try:
            eku_ext = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
            for oid in eku_ext.value:
                if oid == x509.oid.ExtendedKeyUsageOID.SERVER_AUTH:
                    extended_key_usage.append("Server Authentication")
                elif oid == x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH:
                    extended_key_usage.append("Client Authentication")
                elif oid == x509.oid.ExtendedKeyUsageOID.CODE_SIGNING:
                    extended_key_usage.append("Code Signing")
                elif oid == x509.oid.ExtendedKeyUsageOID.EMAIL_PROTECTION:
                    extended_key_usage.append("Email Protection")
        except x509.ExtensionNotFound:
            pass
        
        # Basic Constraints (to check if CA)
        is_ca = False
        ca_path_length = None
        try:
            bc_ext = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
            bc = bc_ext.value
            is_ca = bc.ca
            ca_path_length = bc.path_length
        except x509.ExtensionNotFound:
            pass
        
        # Authority Key Identifier (parent cert identification)
        auth_key_id = None
        try:
            aki_ext = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
            aki = aki_ext.value
            if aki.key_identifier:
                auth_key_id = aki.key_identifier.hex().upper()
        except x509.ExtensionNotFound:
            pass
        
        # Subject Key Identifier
        subject_key_id = None
        try:
            ski_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER)
            ski = ski_ext.value
            if ski.digest:
                subject_key_id = ski.digest.hex().upper()
        except x509.ExtensionNotFound:
            pass
        
        # Public key info
        pub_key = cert.public_key()
        key_type = type(pub_key).__name__
        key_size = 0
        if hasattr(pub_key, 'key_size'):
            key_size = pub_key.key_size
        
        # Signature algorithm
        sig_alg = cert.signature_algorithm_oid._name if hasattr(cert.signature_algorithm_oid, '_name') else str(cert.signature_algorithm_oid)
        
        # Is self-signed
        is_self_signed = cert.issuer == cert.subject
        
        return {
            "index": chain_index,
            "subject": format_certificate_subject(cert),
            "issuer": format_certificate_issuer(cert),
            "version": f"v{cert.version.value}",
            "serial_number": f"{cert.serial_number:X}",
            "not_before": cert.not_valid_before.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "not_after": cert.not_valid_after.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "days_remaining": (cert.not_valid_after - datetime.utcnow()).days,
            "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex().upper(),
            "fingerprint_sha1": cert.fingerprint(hashes.SHA1()).hex().upper(),
            "public_key_type": key_type,
            "public_key_size": key_size,
            "signature_algorithm": sig_alg,
            "subject_alt_names": san_list,
            "key_usage": key_usage,
            "extended_key_usage": extended_key_usage,
            "is_self_signed": is_self_signed,
            "is_ca": is_ca,
            "ca_path_length": ca_path_length,
            "authority_key_identifier": auth_key_id,
            "subject_key_identifier": subject_key_id,
        }
    except Exception as exc:
        return {
            "index": chain_index,
            "error": f"Failed to parse certificate: {str(exc)}"
        }


def get_certificate_chain(host: str, port: int = 443, timeout: int = 10) -> Dict[str, object]:
    """Extract the complete SSL/TLS certificate chain from a server.
    
    Retrieves the full certificate chain including:
    - Leaf certificate (server certificate)
    - Intermediate certificates (if any)
    - Root CA certificate (if available)
    
    Properly handles SNI (Server Name Indication) for accurate certificate retrieval.
    """
    chain_info = []
    cert_index = 0
    
    try:
        # Method 1: Try OpenSSL CLI first with SNI support (most reliable)
        try:
            # OpenSSL s_client with -servername for proper SNI
            result = subprocess.run(
                ['openssl', 's_client', 
                 '-connect', f'{host}:{port}',
                 '-servername', host,  # SNI: Send hostname to server
                 '-showcerts'],
                input=b'',
                capture_output=True,
                timeout=timeout
            )
            
            if result.returncode == 0 or b'-----BEGIN CERTIFICATE-----' in result.stdout:
                output = result.stdout.decode('utf-8', errors='ignore')
                
                # Extract all certificates from output
                cert_blocks = []
                current_block = []
                in_cert = False
                
                for line in output.split('\n'):
                    if '-----BEGIN CERTIFICATE-----' in line:
                        in_cert = True
                        current_block = [line]
                    elif '-----END CERTIFICATE-----' in line:
                        current_block.append(line)
                        cert_blocks.append('\n'.join(current_block))
                        current_block = []
                        in_cert = False
                    elif in_cert:
                        current_block.append(line)
                
                # Process certificates from openssl
                if cert_blocks:
                    for pem_block in cert_blocks:
                        try:
                            pem_bytes = pem_block.encode('utf-8')
                            cert_obj = serialization.load_pem_x509_certificate(
                                pem_bytes, 
                                default_backend()
                            )
                            cert_der = cert_obj.public_bytes(serialization.Encoding.DER)
                            cert_data = extract_certificate_info(cert_der, cert_index)
                            chain_info.append(cert_data)
                            cert_index += 1
                        except Exception:
                            pass  # Skip invalid certificates
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass  # OpenSSL not available, fall back to SSL socket
        
        # Method 2: Fallback to Python SSL socket with proper SNI
        if not chain_info:
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((host, port), timeout=timeout) as sock:
                    # SNI: Pass server_hostname BEFORE wrapping socket
                    # This ensures SNI is sent in ClientHello
                    with context.wrap_socket(sock, server_hostname=host) as ssock:
                        # Get peer certificate
                        peer_cert_der = ssock.getpeercert(binary_form=True)
                        
                        if peer_cert_der:
                            # Extract leaf certificate
                            cert_data = extract_certificate_info(peer_cert_der, 0)
                            chain_info.append(cert_data)
                            cert_index += 1
                        
                        # Try to get additional chain certificates if available
                        try:
                            # Some servers may provide chain info via getpeercert_chain
                            if hasattr(ssock, 'getpeercert_chain'):
                                peer_chain = ssock.getpeercert_chain()
                                if peer_chain and len(peer_chain) > 1:
                                    # Process additional certificates in chain
                                    for chain_cert_der in peer_chain[1:]:
                                        try:
                                            cert_data = extract_certificate_info(chain_cert_der, cert_index)
                                            chain_info.append(cert_data)
                                            cert_index += 1
                                        except Exception:
                                            pass
                        except Exception:
                            pass  # Chain retrieval not always available
                            
            except Exception:
                pass  # If this also fails, error will be returned below
        
        # Return result
        if chain_info:
            return {
                "host": host,
                "port": port,
                "sni_enabled": True,  # Confirm SNI was used
                "chain": chain_info,
                "chain_length": len(chain_info),
                "error": None,
            }
        else:
            return {
                "host": host,
                "port": port,
                "sni_enabled": False,
                "chain": [],
                "chain_length": 0,
                "error": "Could not extract any certificates",
            }
            
    except socket.gaierror as exc:
        return {
            "host": host,
            "port": port,
            "sni_enabled": False,
            "error": f"Host resolution failed: {str(exc)}",
            "chain": [],
        }
    except socket.timeout:
        return {
            "host": host,
            "port": port,
            "sni_enabled": False,
            "error": "Connection timeout",
            "chain": [],
        }
    except Exception as exc:
        return {
            "host": host,
            "port": port,
            "sni_enabled": False,
            "error": f"Failed to connect: {str(exc)}",
            "chain": [],
        }


def get_certificate_type(cert_info: Dict[str, object]) -> str:
    """Determine the type of certificate in the chain.
    
    Returns:
        - "Leaf" for server/end-entity certificates
        - "Intermediate" for intermediate CA certificates
        - "Root CA" for root CA certificates
        - "Self-Signed" for self-signed certificates
    """
    if cert_info.get("is_self_signed"):
        # Check if it's a root CA (has CA:TRUE in Basic Constraints)
        return "Root CA"
    else:
        # It's either a leaf or intermediate certificate
        # Intermediates typically have "Certificate Sign" in Key Usage
        key_usage = cert_info.get("key_usage", [])
        if "Certificate Sign" in key_usage:
            return "Intermediate CA"
        else:
            return "Leaf"


def validate_certificate_chain_integrity(chain_info: Dict[str, object]) -> Dict[str, object]:
    """Validate the integrity and structure of the certificate chain.
    
    Checks:
    - Certificate order (Leaf -> Intermediate -> Root)
    - Subject/Issuer matching
    - Key identifier linking
    - Self-signed root
    """
    chain = chain_info.get("chain", [])
    if not chain:
        return {"valid": False, "message": "Empty certificate chain"}
    
    issues = []
    
    # Check if chain is properly ordered
    if len(chain) > 1:
        for i in range(len(chain) - 1):
            current_cert = chain[i]
            next_cert = chain[i + 1]
            
            # Current issuer should match next certificate's subject
            if current_cert.get("issuer") != next_cert.get("subject"):
                issues.append({
                    "type": "CHAIN_BREAK",
                    "severity": "HIGH",
                    "message": f"Chain break between cert {i} and {i+1}: Issuer mismatch"
                })
    
    # Check if root CA is self-signed
    if len(chain) > 0:
        root = chain[-1]
        if not root.get("is_self_signed"):
            issues.append({
                "type": "NO_SELF_SIGNED_ROOT",
                "severity": "MEDIUM",
                "message": "Root certificate is not self-signed (incomplete chain?)"
            })
    
    # Check key identifier linking
    if len(chain) > 1:
        for i in range(len(chain) - 1):
            current_cert = chain[i]
            next_cert = chain[i + 1]
            
            auth_key_id = current_cert.get("authority_key_identifier")
            subject_key_id = next_cert.get("subject_key_identifier")
            
            if auth_key_id and subject_key_id:
                if auth_key_id != subject_key_id:
                    issues.append({
                        "type": "KEY_ID_MISMATCH",
                        "severity": "MEDIUM",
                        "message": f"Key identifier mismatch between cert {i} and {i+1}"
                    })
    
    chain_status = "VALID" if not issues else "INVALID"
    return {
        "valid": len(issues) == 0,
        "status": chain_status,
        "issues": issues,
        "message": "Certificate chain is properly ordered and linked" if not issues else f"Found {len(issues)} issue(s)"
    }


def analyze_chain_security(chain_info: Dict[str, object]) -> Dict[str, object]:
    """Analyze security posture of certificate chain."""
    issues = []
    warnings = []
    
    if chain_info.get("error"):
        return {
            "error": chain_info["error"],
            "issues": [],
            "warnings": [],
            "security_level": "ERROR"
        }
    
    chain = chain_info.get("chain", [])
    
    if not chain:
        return {
            "error": "Empty certificate chain",
            "issues": [],
            "warnings": [],
            "security_level": "ERROR"
        }
    
    # Analyze each certificate
    for cert_idx, cert_info in enumerate(chain):
        if "error" in cert_info:
            issues.append({
                "certificate": cert_idx,
                "type": "PARSE_ERROR",
                "message": cert_info["error"]
            })
            continue
        
        # Check if expired
        days_remaining = cert_info.get("days_remaining", 0)
        if days_remaining < 0:
            issues.append({
                "certificate": cert_idx,
                "type": "EXPIRED",
                "severity": "CRITICAL",
                "message": f"Certificate expired {abs(days_remaining)} days ago"
            })
        elif days_remaining < 30:
            warnings.append({
                "certificate": cert_idx,
                "type": "EXPIRING_SOON",
                "severity": "HIGH",
                "message": f"Certificate expires in {days_remaining} days"
            })
        
        # Check if self-signed
        if cert_info.get("is_self_signed"):
            warnings.append({
                "certificate": cert_idx,
                "type": "SELF_SIGNED",
                "severity": "MEDIUM",
                "message": "Certificate is self-signed"
            })
        
        # Check public key strength
        key_size = cert_info.get("public_key_size", 0)
        if key_size < 2048:
            issues.append({
                "certificate": cert_idx,
                "type": "WEAK_KEY",
                "severity": "HIGH",
                "message": f"RSA key size is only {key_size} bits (should be >= 2048)"
            })
        elif key_size < 4096:
            warnings.append({
                "certificate": cert_idx,
                "type": "WEAK_KEY",
                "severity": "LOW",
                "message": f"RSA key size is {key_size} bits (2048+ recommended, 4096+ preferred)"
            })
    
    # Determine overall security level
    if issues:
        security_level = "CRITICAL"
    elif warnings:
        security_level = "WARNING"
    else:
        security_level = "SECURE"
    
    return {
        "issues": issues,
        "warnings": warnings,
        "security_level": security_level,
        "chain_length": len(chain),
    }
