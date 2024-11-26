# CertMapper for Recon

A high-performance, multi-threaded SSL certificate scanner that extracts detailed certificate information from IP ranges. This tool is designed for network administrators, security researchers, and IT professionals who need to audit SSL/TLS certificates across their infrastructure.

## Features

- 🚀 Multi-threaded scanning with configurable thread pool
- 📁 Multiple output formats (JSON, CSV, and simple text)
- 📊 Detailed certificate information extraction
- 🔍 Support for multiple ports per IP
- 📈 Progress tracking and statistics
- 🔄 Automatic retry mechanism for failed connections
- 📝 Comprehensive logging
- 📑 Summary report generation
- 🔋 Batch processing for efficient resource usage

## Certificate Information Extracted

- Subject and Issuer Details
  - Common Name (CN)
  - Organization (O)
  - Country (C)
  - Organizational Unit (OU)
- Domain Names
  - Subject Alternative Names (SANs)
  - DNS Names
  - IP Addresses
  - Email Addresses
- Validity
  - Valid From
  - Valid Until
- Technical Details
  - Serial Number
  - Signature Algorithm
  - Version
  - Key Usage
  - Extended Key Usage
  - CA Status
- URLs
  - CA Issuer URLs
  - OCSP URLs
  - CRL Distribution Points

## Requirements

```bash
python >= 3.7
cryptography
pyOpenSSL
```

## Installation

1. Clone the repository:
```bash
git clone https://github.com/iddummyuser/CertMapper.git
cd CertMapper
```

2. Install required packages:
```bash
pip install -r requirements.txt
```

## Usage

1. Create a file containing CIDR ranges (one per line):
```text
192.168.1.0/24
10.0.0.0/16
```

2. Run the scanner:
```bash
python CertMapper.py ranges.txt \
    --ports 443,8443 \
    --threads 20 \
    --timeout 3 \
    --retries 3 \
    --batch-size 100 \
    --output certs.json \
    --csv certs.csv \
    --txt certs.txt \
    --summary summary.json
```

### Command Line Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `cidr_file` | File containing CIDR ranges | (Required) |
| `--ports` | Comma-separated ports to scan | 443,8443 |
| `--threads` | Number of concurrent threads | 10 |
| `--timeout` | Connection timeout in seconds | 3 |
| `--retries` | Number of retry attempts | 3 |
| `--batch-size` | IPs to process per batch | 100 |
| `--output` | JSON output file | certificates.json |
| `--csv` | CSV output file | certificates.csv |
| `--txt` | Simple text output file | certificates.txt |
| `--summary` | Summary report file | summary.json |
| `--log-file` | Log file path | scanner.log |

## Output Formats

### 1. JSON Output (certificates.json)
Detailed certificate information in JSON format:
```json
{
  "ip": "192.168.1.1",
  "scan_time": "2024-11-26T12:00:00",
  "certificates": [
    {
      "port": 443,
      "info": {
        "issuer_cn": "Example CA",
        "subject_cn": "example.com",
        "domains": ["example.com", "www.example.com"],
        ...
      }
    }
  ]
}
```

### 2. CSV Output (certificates.csv)
Structured data in CSV format with headers:
```csv
ip,port,scan_time,issuer_cn,subject_cn,domains,...
"192.168.1.1","443","2024-11-26T12:00:00","Example CA","example.com","example.com;www.example.com",...
```

### 3. Text Output (certificates.txt)
Simple, readable format:
```text
IP=192.168.1.1|Port=443|CN=example.com|Issuer=Example CA|Valid_Until=2025-11-26T12:00:00|SANs=example.com;www.example.com
```

### 4. Summary Report (summary.json)
Statistical overview:
```json
{
  "scan_summary": {
    "total_certificates": 100,
    "unique_domains": 50,
    "unique_cas": 10
  },
  "port_distribution": {
    "443": 80,
    "8443": 20
  },
  "certificate_expiry": {
    "valid": 90,
    "expiring_soon": 8,
    "expired": 2
  }
}
```

## Error Handling

- Connection timeouts
- SSL/TLS handshake failures
- Invalid certificates
- Network errors
- Malformed certificate data

The script includes comprehensive error handling and logging to ensure reliable operation even when encountering problematic certificates or network issues.

## Performance Optimization

- Batch processing to manage memory usage
- Configurable thread pool for parallel scanning
- Connection timeouts to handle unresponsive hosts
- Retry mechanism for transient failures
- Progress tracking for long-running scans


## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [cryptography](https://github.com/pyca/cryptography) library
- [pyOpenSSL](https://github.com/pyca/pyopenssl) library

## Disclaimer

This tool is intended for legitimate security research and network administration. Users are responsible for ensuring they have permission to scan the target networks and comply with all applicable laws and regulations.
