# qport

A fast, passive port scanner using Shodan InternetDB API. This tool efficiently scans large lists of hosts to discover open ports without active scanning, making it ideal for reconnaissance and security assessments.

## Features

- 🚀 **High Performance**: Asynchronous scanning with configurable concurrency (minimum 500)
- 🔍 **Passive Scanning**: Uses Shodan InternetDB API for non-intrusive port discovery
- 📊 **Smart Concurrency**: Automatically calculates optimal concurrency based on target list size
- 🛠️ **Flexible Input**: Supports host lists in text files (one host per line)
- 📝 **Structured Output**: Clean output format with host:port pairs
- 🔧 **System Optimization**: Automatically configures system limits for optimal performance
- 📈 **Progress Tracking**: Real-time status updates during scanning

## Requirements

- Rust 1.70+ (for building from source)
- Internet connection (for Shodan API access)
- Linux or macOS (system optimization features)

## Installation

### Option 1: Build from Source

```bash
# Clone the repository
git clone https://github.com/Twistedmock/qport.git
cd qport

# Build the project
cargo build --release

# The binary will be available at target/release/qport
```

### Option 2: Direct Download

Download the latest release from the [GitHub Releases](https://github.com/Twistedmock/qport/releases) page.

## Usage

### Basic Usage

```bash
# Scan hosts from a file
./qport -i hosts.txt -o results.txt

# Scan with custom concurrency
./qport -i hosts.txt -o results.txt -c 1000

# Enable verbose output
./qport -i hosts.txt -o results.txt -v
```

### Command Line Options

```
Usage: qport [OPTIONS] --input <INPUT> --output <OUTPUT>

Options:
  -i, --input <INPUT>        Input file with list of hosts (one per line)
  -o, --output <OUTPUT>      Output file for results
  -c, --concurrency <CONCURRENCY>
                              Number of concurrent requests (auto-calculated based on input if not specified, minimum 500)
  -v, --verbose              Enable verbose output
  -h, --help                 Print help
  -V, --version              Print version
```

### Input File Format

Create a text file with one host per line:

```
example.com
192.168.1.1
scanme.nmap.org
subdomain.example.org
```

### Output Format

Results are saved in the format `host:port`:

```
example.com:80
example.com:443
192.168.1.1:22
192.168.1.1:80
scanme.nmap.org:22
scanme.nmap.org:80
```

## Concurrency

qport automatically calculates optimal concurrency based on your target list:

- **Formula**: `max(hosts × 0.6 ÷ 60, 500)`
- **Minimum**: 500 concurrent requests
- **Maximum**: Calculated based on target list size (no hard cap)

### Examples:
- 10,000 hosts → ~500 concurrency
- 100,000 hosts → ~1,000 concurrency
- 1,000,000 hosts → ~10,000 concurrency

You can override the auto-calculated value with the `-c` flag, but it will be increased to the minimum of 500 if lower.

## System Requirements

### Linux
The tool automatically configures optimal system settings:
- File descriptor limit: 1,048,576
- TCP settings optimized for high concurrency

### macOS
File descriptor limits are optimized automatically. For maximum performance, you may need to run:
```bash
sudo sysctl -w kern.maxfiles=2097152
sudo sysctl -w kern.maxfilesperproc=1048576
```

## API Rate Limits

qport uses the free Shodan InternetDB API, which has rate limits. For large-scale scanning:
- Space out your scans to avoid hitting rate limits
- Consider using multiple IP addresses if needed
- The tool handles API errors gracefully and continues scanning

## Examples

### Basic Scan
```bash
./qport -i targets.txt -o open_ports.txt
```

### Large-Scale Scan with Custom Concurrency
```bash
./qport -i large_target_list.txt -o results.txt -c 2000 -v
```

### Quick Test
```bash
echo "scanme.nmap.org" > test.txt
./qport -i test.txt -o test_results.txt -v
```

## Troubleshooting

### Common Issues

1. **"Failed to set file descriptor limit"**
   - On Linux: Run with `sudo` or adjust system limits
   - On macOS: The tool will still work but with reduced performance

2. **High memory usage**
   - Reduce concurrency with `-c` flag
   - Process smaller batches of targets

3. **Slow scanning**
   - Check your internet connection
   - You may be hitting Shodan API rate limits
   - Try reducing concurrency

### Verbose Mode

Use the `-v` flag for detailed output including:
- API query URLs
- Error messages for individual hosts
- System configuration status
- Concurrency warnings

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make your changes and test thoroughly
4. Commit your changes: `git commit -am 'Add new feature'`
5. Push to the branch: `git push origin feature-name`
6. Submit a pull request

## License

This project is open source. Please check the license file for details.

## Disclaimer

This tool is for educational and security research purposes only. Users are responsible for complying with applicable laws and regulations when using this tool. The authors are not responsible for any misuse or damage caused by this software.
