# qport

Fast passive port scanner using Shodan InternetDB with stealth features and optimized performance.

## Features

- **Subdomain Support**: Accepts both IPs and subdomains as input - automatically resolves subdomains to IPs and preserves subdomain names in output
- **Sequential Processing**: No concurrency to avoid detection and rate limiting
- **High Performance**: Configurable rate limiting (default: 300 requests per second) with concurrent processing
- **Stealth Mode**: 100 rotating browser user agents to avoid fingerprinting
- **Simple CLI**: Intuitive command-line interface with auto-generated output files
- **Anew-style Output**: Appends only new unique lines to existing output files by default
- **Unique Port Filtering**: Optional filtering to exclude common ports (80, 443)
- **Cross-Platform**: Works on Linux, macOS, and Windows

## Installation

### From Source
```bash
git clone https://github.com/Twistedmock/qport.git
cd qport
cargo build --release
```

The binary will be available at `target/release/qport`

## Usage

### Basic Usage
```bash
# Scan hosts from a file
./qport -i hosts.txt

# Scan with custom output file
./qport -i hosts.txt -o results.txt

# Generate unique results excluding ports 80,443
./qport -i hosts.txt -u unique_ports.txt

# Force overwrite instead of unique-append
./qport -i hosts.txt -o results.txt --overwrite

# Custom request rate (500 requests per second)
./qport -i hosts.txt -t 500

# High concurrency with 100 workers and 1000 RPS
./qport -i hosts.txt -t 1000 -c 100

# Verbose output with debug information
./qport -i hosts.txt -v -d
```

### Command Line Options

- `-i, --input <FILE>`: Input file with list of hosts - supports both IPs and subdomains (one per line)
- `-o, --output <FILE>`: Output file for results (optional, auto-generated if not provided)
- `-u, --uniq <FILE>`: Generate unique output file excluding common ports 80,443
- `--overwrite`: Overwrite output files instead of the default unique-append behavior
- `-v, --verbose`: Enable verbose output
- `-d, --debug`: Enable debug output with detailed statistics
- `-s, --silent`: Suppress results output to terminal
- `-t, --rps <NUMBER>`: Maximum requests per second (default: 300)
- `-c, --concurrency <NUMBER>`: Number of concurrent workers (default: 50)

### Input Format

Create a text file with one host per line. **Both IP addresses and subdomains are supported**:
```
example.com
192.168.1.1
subdomain.example.org
api.service.com
10.0.0.1
```

### Output Format

Results are saved in `host:port` format. **Subdomains are preserved in the output** (not converted to IPs):
```
example.com:22
example.com:80
example.com:443
subdomain.example.org:8080
subdomain.example.org:8443
192.168.1.1:21
192.168.1.1:22
```

**How subdomain scanning works:**
1. Tool accepts subdomain as input (e.g., `api.example.com`)
2. Resolves subdomain to IP address(es) internally
3. Queries Shodan InternetDB with resolved IP(s) to find open ports
4. Outputs results as `subdomain:port` (preserving the original subdomain name)

When an output file already exists, qport appends only lines that are not already present (unique by full line), similar to tomnomnom's "anew". This prevents duplicate results across multiple runs. Use `--overwrite` to write a fresh file instead.

## Performance

- **Speed**: Configurable rate limiting (default: 300 RPS, adjustable via -t flag)
- **Stealth**: 100 different browser user agents rotated per request
- **Efficiency**: Sequential processing prevents rate limiting
- **System Optimization**: Automatic file descriptor limit configuration

## Technical Details

- **Language**: Rust 2021 Edition
- **HTTP Client**: reqwest with custom headers and timeouts
- **Async Runtime**: tokio for efficient I/O operations
- **CLI Framework**: clap 4.0 with derive macros
- **Data Source**: Shodan InternetDB (free, no API key required)

## Why qport?

Unlike aggressive concurrent scanners that get blocked, qport uses a "portmap-like" approach:
- Sequential requests instead of parallel flooding
- Realistic browser user agents instead of tool fingerprints
- Random delays to mimic human browsing patterns
- Automatic retry logic with exponential backoff

This approach achieves high success rates while maintaining reasonable speed.

## License

MIT License - see LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## Disclaimer

This tool is for educational and authorized security testing purposes only. Always ensure you have permission to scan target systems.
