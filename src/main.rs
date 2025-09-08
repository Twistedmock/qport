use clap::Parser;
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::time::Duration;
use rand::Rng;

#[derive(Parser)]
#[command(name = "qport")]
#[command(about = "Fast passive port scanner using Shodan InternetDB")]
struct Args {
    /// Input file with list of hosts (one per line)
    #[arg(short, long)]
    input: String,

    /// Output file for results (optional, auto-generated if not provided)
    #[arg(short, long)]
    output: Option<String>,

    /// Enable verbose output
    #[arg(short, long)]
    verbose: bool,

    /// Enable debug output with detailed statistics
    #[arg(short = 'd', long)]
    debug: bool,

    /// Suppress results output to terminal
    #[arg(short, long)]
    silent: bool,

    /// Generate unique output file excluding common ports 80,443
    #[arg(short = 'u', long, value_name = "UNIQUE_FILE")]
    uniq: Option<String>,
}

#[derive(Deserialize, Clone)]
struct ShodanResult {
    ip: String,
    ports: Vec<u16>,
    hostnames: Vec<String>,
}

fn get_user_agents() -> Vec<&'static str> {
    vec![
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.59",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.63 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.61 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:90.0) Gecko/20100101 Firefox/90.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:92.0) Gecko/20100101 Firefox/92.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.63 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.63 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/93.0",
        "Mozilla/5.0 (X11; Linux x86_64; rv:90.0) Gecko/20100101 Firefox/90.0",
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_5_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:94.0) Gecko/20100101 Firefox/94.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.61 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.61 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.82 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:95.0) Gecko/20100101 Firefox/95.0",
        "Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0",
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.63 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:92.0) Gecko/20100101 Firefox/92.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:96.0) Gecko/20100101 Firefox/96.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.60 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:97.0) Gecko/20100101 Firefox/97.0",
        "Mozilla/5.0 (X11; Linux x86_64; rv:92.0) Gecko/20100101 Firefox/92.0",
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.61 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_5_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.41 Safari/537.36",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:93.0) Gecko/20100101 Firefox/93.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:98.0) Gecko/20100101 Firefox/98.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.63 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.2 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:99.0) Gecko/20100101 Firefox/99.0",
        "Mozilla/5.0 (X11; Linux x86_64; rv:93.0) Gecko/20100101 Firefox/93.0",
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_6_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.1 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.53 Safari/537.36",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:94.0) Gecko/20100101 Firefox/94.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:100.0) Gecko/20100101 Firefox/100.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.63 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.81 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.63 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:101.0) Gecko/20100101 Firefox/101.0",
        "Mozilla/5.0 (X11; Linux x86_64; rv:94.0) Gecko/20100101 Firefox/94.0",
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_6_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.2 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:95.0) Gecko/20100101 Firefox/95.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.82 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.82 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:103.0) Gecko/20100101 Firefox/103.0",
        "Mozilla/5.0 (X11; Linux x86_64; rv:95.0) Gecko/20100101 Firefox/95.0",
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_0_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.1 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:96.0) Gecko/20100101 Firefox/96.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:104.0) Gecko/20100101 Firefox/104.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.61 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.61 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0",
        "Mozilla/5.0 (X11; Linux x86_64; rv:96.0) Gecko/20100101 Firefox/96.0",
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.82 Safari/537.36"
    ]
}

fn configure_system(verbose: bool) -> io::Result<()> {
    unsafe {
        let target_limit = 1_048_576;
        let rlimit = libc::rlimit {
            rlim_cur: target_limit,
            rlim_max: target_limit,
        };
        if libc::setrlimit(libc::RLIMIT_NOFILE, &rlimit) != 0 {
            let err = io::Error::last_os_error();
            if verbose {
                eprintln!(
                    "Failed to set file descriptor limit to {}. Run 'ulimit -n {}' manually: {}",
                    target_limit, target_limit, err
                );
            }
            return Err(err);
        }
        if verbose {
            println!("Set file descriptor limit to {}", target_limit);
        }
    }

    #[cfg(target_os = "linux")]
    {
        let sysctl_settings = [
            ("net.ipv4.ip_local_port_range", "10000 65535"),
            ("net.ipv4.tcp_fin_timeout", "15"),
            ("net.ipv4.tcp_tw_reuse", "1"),
            ("fs.file-max", "2097152"),
        ];
        for (key, value) in sysctl_settings.iter() {
            let cmd = std::process::Command::new("sysctl")
                .arg("-w")
                .arg(format!("{}={}", key, value))
                .output();
            match cmd {
                Ok(output) if output.status.success() => {
                    if verbose {
                        println!("Set {} = {}", key, value);
                    }
                }
                Ok(output) => {
                    let err = String::from_utf8_lossy(&output.stderr);
                    if verbose {
                        eprintln!(
                            "Failed to set {} = {}. Run 'sudo sysctl -w {}={}' manually: {}",
                            key, value, key, value, err
                        );
                    }
                }
                Err(e) => {
                    if verbose {
                        eprintln!(
                            "Failed to run sysctl for {} = {}: {}. Run 'sudo sysctl -w {}={}' manually",
                            key, value, e, key, value
                        );
                    }
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        if verbose {
            println!("TCP settings (e.g., port range, TCP reuse) are Linux-specific and not applied on macOS.");
            println!("To increase file descriptors on macOS, run:");
            println!("  sudo sysctl -w kern.maxfiles=2097152");
            println!("  sudo sysctl -w kern.maxfilesperproc=1048576");
        }
    }

    Ok(())
}

async fn resolve_host(host: &str) -> Vec<String> {
    let mut ips = vec![];
    match tokio::net::lookup_host((host, 0)).await {
        Ok(addrs) => {
            for addr in addrs {
                ips.push(addr.ip().to_string());
            }
        }
        Err(_) => {
            // If not resolvable, assume it's an IP
            ips.push(host.to_string());
        }
    }
    ips
}

async fn query_shodan(client: &Client, ip: &str, user_agent: &str, verbose: bool) -> Result<ShodanResult, Box<dyn std::error::Error + Send + Sync>> {
    let url = format!("https://internetdb.shodan.io/{}", ip);
    let mut retries = 0;
    const MAX_RETRIES: u32 = 2;
    
    loop {
        if verbose {
            println!("Querying: {} (attempt {}) with UA: {}", url, retries + 1, &user_agent[..50]);
        }
        
        let resp = client
            .get(&url)
            .header("User-Agent", user_agent)
            .send()
            .await?;
        
        if resp.status().is_success() {
            let result: ShodanResult = resp.json().await?;
            return Ok(result);
        } else if resp.status().as_u16() == 429 {
            retries += 1;
            if retries <= MAX_RETRIES {
                if verbose {
                    println!("Rate limited (429) for {}, cooling down for 1s (attempt {}/{})", ip, retries, MAX_RETRIES);
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            } else {
                return Err(format!("Rate limited (429) for {} after {} retries", ip, MAX_RETRIES).into());
            }
        } else {
            return Err(format!("HTTP {} for {}", resp.status(), ip).into());
        }
    }
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let args = Args::parse();
    let start_time = std::time::Instant::now();

    // Auto-generate output filename if not provided
    let output_filename = args.output.unwrap_or_else(|| {
        if args.input.ends_with(".txt") {
            args.input.replace(".txt", "_results.txt")
        } else {
            format!("{}_results.txt", args.input)
        }
    });

    let num_hosts = {
        let file = File::open(&args.input)?;
        let reader = BufReader::new(file);
        reader.lines().count()
    };

    println!("Input has {} hosts", num_hosts);

    if args.debug {
        println!("Debug mode enabled - showing detailed statistics");
    }

    configure_system(args.verbose)?;

    // Create HTTP client without default user agent since we'll rotate them
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .expect("Failed to build HTTP client");

    // Get the list of user agents for rotation
    let user_agents = get_user_agents();

    let file = File::open(&args.input)?;
    let reader = BufReader::new(file);

    let mut processed_hosts = 0;
    let mut successful_queries = 0;
    let mut failed_queries = 0;
    let mut all_results = HashMap::new();
    let mut request_count = 0; // Counter for user agent rotation

    // Sequential processing like portmap - no concurrency
    for line in reader.lines() {
        let line = line?;
        let host = line.trim().to_string();
        if host.is_empty() {
            continue;
        }
        processed_hosts += 1;

        if args.debug {
            println!("Processing host {} ({}/{})", host, processed_hosts, num_hosts);
        }

        // Resolve host to IPs
        let ips = resolve_host(&host).await;
        let mut host_results = vec![];
        let mut host_success_count = 0;
        let mut host_fail_count = 0;

        for ip in ips {
            // Ultra fast delay for ~500 requests per second (2ms average)
            let jitter = rand::thread_rng().gen_range(1..3);
            tokio::time::sleep(Duration::from_millis(jitter)).await;
            
            // Rotate user agents for each request
            let user_agent = user_agents[request_count % user_agents.len()];
            request_count += 1;
            
            match query_shodan(&client, &ip, user_agent, args.verbose).await {
                Ok(result) => {
                    let ports_count = result.ports.len();
                    host_results.push((ip.clone(), result.ports));
                    host_success_count += 1;
                    if args.debug {
                        println!("✓ {}: {} ports found", ip, ports_count);
                    }
                }
                Err(e) => {
                    host_fail_count += 1;
                    if args.verbose {
                        eprintln!("✗ Error querying {}: {}", ip, e);
                    }
                }
            }
        }

        all_results.insert(host.clone(), host_results);
        successful_queries += host_success_count;
        failed_queries += host_fail_count;

        if args.debug && (host_success_count > 0 || host_fail_count > 0) {
            println!("Host {}: {} success, {} failed", host, host_success_count, host_fail_count);
        }
    }

    let mut total_ports = 0;
    let mut unique_ports = 0;
    let mut output_file = File::create(&output_filename)?;
    let mut unique_output_file = if let Some(unique_filename) = &args.uniq {
        Some(File::create(unique_filename)?)
    } else {
        None
    };

    for (host, ip_ports) in &all_results {
        for (_ip, ports) in ip_ports {
            for port in ports {
                let result_line = format!("{}:{}", host, port);
                writeln!(output_file, "{}", result_line)?;
                if !args.silent {
                    println!("{}", result_line);
                }
                total_ports += 1;

                // Write to unique output file if enabled and port is not 80 or 443
                if let Some(ref mut unique_file) = unique_output_file {
                    if *port != 80 && *port != 443 {
                        writeln!(unique_file, "{}", result_line)?;
                        unique_ports += 1;
                    }
                }
            }
        }
    }

    let elapsed = start_time.elapsed();

    if args.debug || args.verbose {
        println!("\n--- Debug Statistics ---");
        println!("Total hosts processed: {}", processed_hosts);
        println!("Successful queries: {}", successful_queries);
        println!("Failed queries: {}", failed_queries);
        println!("Total ports found: {}", total_ports);
        if args.uniq.is_some() {
            println!("Unique ports found (excluding 80,443): {}", unique_ports);
        }
        println!("Scan duration: {:.2}s", elapsed.as_secs_f64());
        println!("Average ports per host: {:.2}", if processed_hosts > 0 { total_ports as f64 / processed_hosts as f64 } else { 0.0 });
        println!("Query success rate: {:.1}%", if (successful_queries + failed_queries) > 0 { (successful_queries as f64 / (successful_queries + failed_queries) as f64) * 100.0 } else { 0.0 });
    }

    if !args.silent {
        println!("\nResults saved to: {}", output_filename);
        if let Some(unique_filename) = &args.uniq {
            println!("Unique results (excluding ports 80,443) saved to: {}", unique_filename);
            println!("Found {} open ports ({} unique) across {} hosts in {:.2}s", total_ports, unique_ports, processed_hosts, elapsed.as_secs_f64());
        } else {
            println!("Found {} open ports across {} hosts in {:.2}s", total_ports, processed_hosts, elapsed.as_secs_f64());
        }
    }

    Ok(())
}

