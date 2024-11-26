import socket
import ssl
import ipaddress
import concurrent.futures
import queue
import threading
import time
from typing import List, Optional, Dict, Any, Set
import argparse
import logging
from datetime import datetime
import json
from dataclasses import dataclass, asdict
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.backends import default_backend
import OpenSSL.crypto
from collections import defaultdict

@dataclass
class CertificateInfo:
    origin_ip: str
    issuer_cn: str
    issuer_org: List[str]
    issuer_country: str
    subject_cn: str
    subject_org: List[str]
    subject_country: str
    domains: List[str]
    san_dns_names: List[str]
    san_ip_addresses: List[str]
    san_email_addresses: List[str]
    valid_from: str
    valid_until: str
    serial_number: str
    signature_algorithm: str
    version: int
    ca_issuer_urls: List[str]
    ocsp_urls: List[str]
    crl_urls: List[str]
    key_usage: List[str]
    extended_key_usage: List[str]
    is_ca: bool

class ScannerThread(threading.Thread):
    def __init__(self, input_queue: queue.Queue, result_queue: queue.Queue, 
                 ports: List[int], timeout: int, max_retries: int = 3):
        super().__init__()
        self.input_queue = input_queue
        self.result_queue = result_queue
        self.ports = ports
        self.timeout = timeout
        self.max_retries = max_retries
        self._stop_event = threading.Event()

    def stop(self):
        self._stop_event.set()

    def stopped(self):
        return self._stop_event.is_set()

    def run(self):
        while not self.stopped():
            try:
                ip = self.input_queue.get_nowait()
            except queue.Empty:
                break

            result = self.scan_ip(ip)
            self.result_queue.put(result)
            self.input_queue.task_done()

    def scan_ip(self, ip: str) -> Dict[str, Any]:
        result = {
            'ip': ip,
            'scan_time': datetime.now().isoformat(),
            'certificates': []
        }

        for port in self.ports:
            retries = 0
            while retries < self.max_retries:
                try:
                    cert_info = get_ssl_cert(ip, port, self.timeout)
                    if cert_info:
                        # disable comment to get to see the progresss if you can't wait 🧑‍💻 :)
                        # print({
                        #     'port': port,
                        #     'info': asdict(cert_info)
                        # })
                        result['certificates'].append({
                            'port': port,
                            'info': asdict(cert_info)
                        })
                        break
                except Exception as e:
                    retries += 1
                    if retries == self.max_retries:
                        logging.error(f"Error scanning {ip}:{port} after {retries} retries - {str(e)}")
                    time.sleep(1)  # Add delay between retries

        return result

class CertificateScanner:
    def __init__(self, num_threads: int, ports: List[int], timeout: int, 
                 max_retries: int = 3, batch_size: int = 100):
        self.num_threads = num_threads
        self.ports = ports
        self.timeout = timeout
        self.max_retries = max_retries
        self.batch_size = batch_size
        self.input_queue = queue.Queue()
        self.result_queue = queue.Queue()
        self.threads = []
        self.results = []

    def add_ips(self, ips: List[str]):
        """Add IPs to the scan queue."""
        for ip in ips:
            self.input_queue.put(ip)

    def start_threads(self):
        """Start scanner threads."""
        self.threads = []
        for _ in range(self.num_threads):
            thread = ScannerThread(
                self.input_queue, 
                self.result_queue, 
                self.ports, 
                self.timeout, 
                self.max_retries
            )
            thread.start()
            self.threads.append(thread)

    def stop_threads(self):
        """Stop all scanner threads."""
        for thread in self.threads:
            thread.stop()
        for thread in self.threads:
            thread.join()

    def process_results(self):
        """Process results from the result queue."""
        while True:
            try:
                result = self.result_queue.get_nowait()
                self.results.append(result)
                self.result_queue.task_done()
            except queue.Empty:
                break

    def scan(self, ips: List[str]) -> List[Dict]:
        """Perform the scan operation."""
        total_ips = len(ips)
        processed_ips = 0
        
        # Process IPs in batches
        for i in range(0, total_ips, self.batch_size):
            batch = ips[i:i + self.batch_size]
            self.add_ips(batch)
            
            # Start threads for this batch
            self.start_threads()
            
            # Wait for current batch to complete
            self.input_queue.join()
            
            # Process results
            self.process_results()
            
            # Stop threads
            self.stop_threads()
            
            # Update progress
            processed_ips += len(batch)
            progress = (processed_ips / total_ips) * 100
            logging.info(f"Progress: {progress:.2f}% ({processed_ips}/{total_ips} IPs)")
        
        return self.results
    
def setup_logging(log_file: str):
    """Configure logging to both file and console."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )

def parse_cidr_file(filename: str) -> List[str]:
    """Parse CIDR ranges from file and expand into individual IPs."""
    with open(filename, 'r') as f:
        cidrs = [line.strip() for line in f if line.strip()]
    
    ips = []
    for cidr in cidrs:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            ips.extend(str(ip) for ip in network)
        except ValueError as e:
            logging.error(f"Invalid CIDR notation: {cidr} - {str(e)}")
    return ips

def get_extension_value(cert: x509.Certificate, oid: x509.ObjectIdentifier) -> Optional[x509.Extension]:
    """Safely get certificate extension value."""
    try:
        return cert.extensions.get_extension_for_oid(oid)
    except x509.ExtensionNotFound:
        return None

def safe_get_attributes(name: x509.Name, oid: x509.ObjectIdentifier) -> List[str]:
    """Safely get attributes from certificate name object."""
    try:
        if not name or not oid:
            return []
        attrs = name.get_attributes_for_oid(oid)
        return [str(attr.value) if hasattr(attr, 'value') else str(attr) for attr in attrs]
    except Exception as e:
        logging.debug(f"Error getting attributes for OID {oid}: {str(e)}")
        return []

def safe_get_common_name(name: x509.Name) -> str:
    """Safely get common name from certificate name object."""
    try:
        if not name:
            return ""
        cn_attrs = safe_get_attributes(name, NameOID.COMMON_NAME)
        return str(cn_attrs[0]) if cn_attrs else ""
    except Exception as e:
        logging.debug(f"Error getting common name: {str(e)}")
        return ""

def safe_get_value(obj: Any, attr: str, default: Any = None) -> Any:
    """Safely get value from object attribute."""
    try:
        value = getattr(obj, attr, default)
        return str(value) if value is not None else default
    except Exception:
        return default

def safe_convert_datetime(dt) -> str:
    """Safely convert datetime object to ISO format string."""
    try:
        if hasattr(dt, 'isoformat'):
            return dt.isoformat()
        return str(dt)
    except Exception:
        return ""

def safe_format_serial(serial_number) -> str:
    """Safely format serial number."""
    try:
        if isinstance(serial_number, (int, str)):
            return format(int(str(serial_number), 16) if isinstance(serial_number, str) else serial_number, 'x')
        return ""
    except Exception:
        return ""

def safe_get_san_values(san, san_type) -> List[str]:
    """Safely get SAN values of specific type."""
    try:
        if not san:
            return []
        values = san.get_values_for_type(san_type)
        if san_type == x509.IPAddress:
            return [str(ip.exploded) if hasattr(ip, 'exploded') else str(ip) for ip in values]
        return [str(val.value) if hasattr(val, 'value') else str(val) for val in values]
    except Exception as e:
        logging.debug(f"Error getting SAN values for type {san_type}: {str(e)}")
        return []

def extract_cert_info(der_cert: bytes, ip: str) -> CertificateInfo:
    """Extract detailed certificate information with enhanced error handling."""
    try:
        cert = x509.load_der_x509_certificate(der_cert, default_backend())
        
        # Extract Subject Alternative Names
        san_dns_names = []
        san_ips = []
        san_emails = []
        san_ext = get_extension_value(cert, ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        if san_ext:
            san = san_ext.value
            san_dns_names = safe_get_san_values(san, x509.DNSName)
            san_ips = safe_get_san_values(san, x509.IPAddress)
            san_emails = safe_get_san_values(san, x509.RFC822Name)

        # Extract Authority Information Access
        aia_ext = get_extension_value(cert, ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
        ca_issuer_urls = []
        ocsp_urls = []
        if aia_ext and hasattr(aia_ext, 'value'):
            try:
                for desc in aia_ext.value:
                    if hasattr(desc, 'access_method') and hasattr(desc, 'access_location'):
                        if desc.access_method == x509.oid.AuthorityInformationAccessOID.CA_ISSUERS:
                            ca_issuer_urls.append(str(desc.access_location.value))
                        elif desc.access_method == x509.oid.AuthorityInformationAccessOID.OCSP:
                            ocsp_urls.append(str(desc.access_location.value))
            except Exception as e:
                logging.debug(f"Error extracting AIA: {str(e)}")

        # Extract CRL Distribution Points
        crl_ext = get_extension_value(cert, ExtensionOID.CRL_DISTRIBUTION_POINTS)
        crl_urls = []
        if crl_ext and hasattr(crl_ext, 'value'):
            try:
                for dist_point in crl_ext.value:
                    if hasattr(dist_point, 'full_name'):
                        for name in dist_point.full_name or []:
                            if isinstance(name, x509.UniformResourceIdentifier):
                                crl_urls.append(str(name.value))
            except Exception as e:
                logging.debug(f"Error extracting CRL URLs: {str(e)}")

        # Extract Key Usage
        key_usage = []
        key_usage_ext = get_extension_value(cert, ExtensionOID.KEY_USAGE)
        if key_usage_ext and hasattr(key_usage_ext, 'value'):
            try:
                usage = key_usage_ext.value
                key_usage = [
                    str(attr) for attr in dir(usage) 
                    if not attr.startswith('_') and getattr(usage, attr, False)
                ]
            except Exception as e:
                logging.debug(f"Error extracting key usage: {str(e)}")

        # Extract Extended Key Usage
        ext_key_usage = []
        ext_key_usage_ext = get_extension_value(cert, ExtensionOID.EXTENDED_KEY_USAGE)
        if ext_key_usage_ext and hasattr(ext_key_usage_ext, 'value'):
            try:
                ext_key_usage = [
                    str(getattr(oid, '_name', str(oid))) 
                    for oid in ext_key_usage_ext.value
                ]
            except Exception as e:
                logging.debug(f"Error extracting extended key usage: {str(e)}")

        # Extract Basic Constraints
        is_ca = False
        basic_constraints_ext = get_extension_value(cert, ExtensionOID.BASIC_CONSTRAINTS)
        if basic_constraints_ext and hasattr(basic_constraints_ext, 'value'):
            try:
                is_ca = bool(basic_constraints_ext.value.ca)
            except Exception:
                is_ca = False

        # Get subject common name
        subject_cn = safe_get_common_name(cert.subject)
        
        # Get all domains (combining CN and SANs)
        domains = list(set(san_dns_names + ([subject_cn] if subject_cn else [])))

        return CertificateInfo(
            origin_ip=str(ip),
            issuer_cn=safe_get_common_name(cert.issuer),
            issuer_org=safe_get_attributes(cert.issuer, NameOID.ORGANIZATION_NAME),
            issuer_country=next(iter(safe_get_attributes(cert.issuer, NameOID.COUNTRY_NAME)), ""),
            subject_cn=subject_cn,
            subject_org=safe_get_attributes(cert.subject, NameOID.ORGANIZATION_NAME),
            subject_country=next(iter(safe_get_attributes(cert.subject, NameOID.COUNTRY_NAME)), ""),
            domains=domains,
            san_dns_names=san_dns_names,
            san_ip_addresses=san_ips,
            san_email_addresses=san_emails,
            valid_from=safe_convert_datetime(cert.not_valid_before),
            valid_until=safe_convert_datetime(cert.not_valid_after),
            serial_number=safe_format_serial(cert.serial_number),
            signature_algorithm=str(getattr(cert.signature_algorithm_oid, '_name', '')),
            version=int(safe_get_value(cert.version, 'value', 0)),
            ca_issuer_urls=ca_issuer_urls,
            ocsp_urls=ocsp_urls,
            crl_urls=crl_urls,
            key_usage=key_usage,
            extended_key_usage=ext_key_usage,
            is_ca=is_ca
        )
    except Exception as e:
        logging.error(f"Error extracting certificate info for {ip}: {str(e)}")
        # Return a default CertificateInfo object with empty values
        return CertificateInfo(
            origin_ip=str(ip),
            issuer_cn="",
            issuer_org=[],
            issuer_country="",
            subject_cn="",
            subject_org=[],
            subject_country="",
            domains=[],
            san_dns_names=[],
            san_ip_addresses=[],
            san_email_addresses=[],
            valid_from="",
            valid_until="",
            serial_number="",
            signature_algorithm="",
            version=0,
            ca_issuer_urls=[],
            ocsp_urls=[],
            crl_urls=[],
            key_usage=[],
            extended_key_usage=[],
            is_ca=False
        )

def get_ssl_cert(ip: str, port: int, timeout: int = 3) -> Optional[CertificateInfo]:
    """Retrieve SSL certificate from the specified IP and port."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                if not der_cert:
                    return None
                return extract_cert_info(der_cert, ip)
    except (socket.timeout, ssl.SSLError, ConnectionRefusedError) as e:
        logging.debug(f"Failed to connect to {ip}:{port} - {str(e)}")
        return None
    except Exception as e:
        logging.error(f"Unexpected error for {ip}:{port} - {str(e)}")
        return None
    
def save_to_json(results: List[Dict], output_file: str):
    """Save results to JSON file."""
    try:
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        logging.info(f"JSON results saved to {output_file}")
    except Exception as e:
        logging.error(f"Error saving JSON file: {str(e)}")

def save_to_csv(results: List[Dict], output_file: str):
    """Save scan results to CSV file."""
    import csv
    
    headers = [
        'ip', 'port', 'scan_time', 'issuer_cn', 'issuer_org', 'issuer_country',
        'subject_cn', 'subject_org', 'subject_country', 'domains', 'san_dns_names',
        'san_ip_addresses', 'san_email_addresses', 'valid_from', 'valid_until',
        'serial_number', 'signature_algorithm', 'version', 'ca_issuer_urls',
        'ocsp_urls', 'crl_urls', 'key_usage', 'extended_key_usage', 'is_ca'
    ]
    
    try:
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f, quoting=csv.QUOTE_ALL)
            writer.writerow(headers)
            
            for result in results:
                for cert in result.get('certificates', []):
                    info = cert['info']
                    row = [
                        result['ip'],
                        cert['port'],
                        result['scan_time'],
                        info['issuer_cn'],
                        ';'.join(info['issuer_org']),
                        info['issuer_country'],
                        info['subject_cn'],
                        ';'.join(info['subject_org']),
                        info['subject_country'],
                        ';'.join(info['domains']),
                        ';'.join(info['san_dns_names']),
                        ';'.join(info['san_ip_addresses']),
                        ';'.join(info['san_email_addresses']),
                        info['valid_from'],
                        info['valid_until'],
                        info['serial_number'],
                        info['signature_algorithm'],
                        info['version'],
                        ';'.join(info['ca_issuer_urls']),
                        ';'.join(info['ocsp_urls']),
                        ';'.join(info['crl_urls']),
                        ';'.join(info['key_usage']),
                        ';'.join(info['extended_key_usage']),
                        info['is_ca']
                    ]
                    writer.writerow(row)
        logging.info(f"CSV results saved to {output_file}")
    except Exception as e:
        logging.error(f"Error saving CSV file: {str(e)}")

def save_to_simple_txt(results: List[Dict], output_file: str):
    """Save scan results to a simple text file with basic information."""
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            for result in results:
                for cert in result.get('certificates', []):
                    info = cert['info']
                    basic_info = [
                        f"IP={result['ip']}",
                        f"Port={cert['port']}",
                        f"CN={info['subject_cn']}",
                        f"Issuer={info['issuer_cn']}",
                        f"Valid_Until={info['valid_until']}",
                        f"SANs={';'.join(info['san_dns_names'])}"
                    ]
                    f.write('|'.join(basic_info) + '\n')
        logging.info(f"Simple text results saved to {output_file}")
    except Exception as e:
        logging.error(f"Error saving text file: {str(e)}")

def generate_summary_report(results: List[Dict], output_file: str):
    """Generate and save summary report."""
    try:
        summary = defaultdict(int)
        unique_domains = set()
        unique_cas = set()
        port_distribution = defaultdict(int)
        cert_expiry = defaultdict(int)
        
        for result in results:
            for cert in result.get('certificates', []):
                info = cert['info']
                summary['total_certificates'] += 1
                port_distribution[cert['port']] += 1
                
                # Certificate authorities
                summary['total_cas'] += 1 if info['is_ca'] else 0
                if info['issuer_org']:
                    unique_cas.add(info['issuer_org'][0])
                elif info['issuer_cn']:
                    unique_cas.add(info['issuer_cn'])
                
                # Domains
                unique_domains.update(info['domains'])
                
                # Certificate expiry
                try:
                    expiry_date = datetime.fromisoformat(info['valid_until'])
                    now = datetime.now()
                    days_until_expiry = (expiry_date - now).days
                    
                    if days_until_expiry < 0:
                        cert_expiry['expired'] += 1
                    elif days_until_expiry < 30:
                        cert_expiry['expiring_soon'] += 1
                    else:
                        cert_expiry['valid'] += 1
                except Exception:
                    cert_expiry['unknown'] += 1
        
        summary_report = {
            'scan_summary': {
                'total_certificates': summary['total_certificates'],
                'unique_domains': len(unique_domains),
                'unique_cas': len(unique_cas),
                'total_cas': summary['total_cas']
            },
            'port_distribution': dict(port_distribution),
            'certificate_expiry': dict(cert_expiry),
            'top_domains': list(unique_domains)[:10],  # List top 10 domains
            'top_cas': list(unique_cas)[:10]  # List top 10 CAs
        }
        
        with open(output_file, 'w') as f:
            json.dump(summary_report, f, indent=2)
        
        logging.info(f"Summary report saved to {output_file}")
    except Exception as e:
        logging.error(f"Error generating summary report: {str(e)}")

def main():
    parser = argparse.ArgumentParser(description='Enhanced SSL Certificate Scanner')
    parser.add_argument('cidr_file', help='File containing CIDR ranges')
    parser.add_argument('--ports', default='443,8443', help='Comma-separated ports to scan')
    parser.add_argument('--threads', type=int, default=10, help='Number of concurrent threads')
    parser.add_argument('--timeout', type=int, default=3, help='Timeout in seconds for each connection')
    parser.add_argument('--retries', type=int, default=3, help='Number of retries for failed connections')
    parser.add_argument('--batch-size', type=int, default=100, help='Number of IPs to process in each batch')
    parser.add_argument('--output', default='certificates.json', help='Output JSON file')
    parser.add_argument('--csv', default='certificates.csv', help='Output CSV file')
    parser.add_argument('--txt', default='certificates.txt', help='Output simple text file')
    parser.add_argument('--log-file', default='scanner.log', help='Log file path')
    parser.add_argument('--summary', default='summary.json', help='Summary report output file')
    args = parser.parse_args()

    # Setup logging
    setup_logging(args.log_file)
    
    # Parse ports and CIDR ranges
    try:
        ports = [int(p.strip()) for p in args.ports.split(',')]
    except ValueError as e:
        logging.error(f"Invalid port number: {str(e)}")
        return
    
    try:
        ips = parse_cidr_file(args.cidr_file)
        if not ips:
            logging.error("No valid IPs found in CIDR file")
            return
    except Exception as e:
        logging.error(f"Error parsing CIDR file: {str(e)}")
        return
    
    logging.info(f"Starting scan of {len(ips)} IPs across ports {ports}")
    start_time = time.time()
    
    # Initialize and run scanner
    scanner = CertificateScanner(
        num_threads=args.threads,
        ports=ports,
        timeout=args.timeout,
        max_retries=args.retries,
        batch_size=args.batch_size
    )
    
    try:
        results = scanner.scan(ips)
        
        # Save results in different formats
        save_to_json(results, args.output)
        save_to_csv(results, args.csv)
        save_to_simple_txt(results, args.txt)
        generate_summary_report(results, args.summary)
        
        # Print final statistics
        end_time = time.time()
        duration = end_time - start_time
        total_certs = sum(len(r.get('certificates', [])) for r in results)
        
        logging.info(f"\nScan completed successfully:")
        logging.info(f"Total time: {duration:.2f} seconds")
        logging.info(f"Total IPs scanned: {len(ips)}")
        logging.info(f"Total certificates found: {total_certs}")
        logging.info(f"Average time per IP: {duration/len(ips):.2f} seconds")
        logging.info(f"\nResults saved to:")
        logging.info(f"- JSON: {args.output}")
        logging.info(f"- CSV: {args.csv}")
        logging.info(f"- Text: {args.txt}")
        logging.info(f"- Summary: {args.summary}")
        
    except KeyboardInterrupt:
        logging.info("\nScan interrupted by user. Saving partial results...")
        save_to_json(scanner.results, args.output + '.partial')
        save_to_csv(scanner.results, args.csv + '.partial')
        save_to_simple_txt(scanner.results, args.txt + '.partial')
        generate_summary_report(scanner.results, args.summary + '.partial')
        logging.info("Partial results saved. Exiting...")
    except Exception as e:
        logging.error(f"Error during scan: {str(e)}")

if __name__ == "__main__":
    main()
