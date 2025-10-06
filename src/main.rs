use clap::Parser;
use reqwest::Client;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::{interval, MissedTickBehavior};
use tokio::sync::{Mutex, Semaphore};
use indicatif::{ProgressBar, ProgressStyle};

#[derive(Parser)]
#[command(name = "qport")]
#[command(about = "Fast passive port scanner using Shodan InternetDB")]
struct Args {
    /// Input file with list of hosts - supports both IPs and subdomains (one per line)
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

    /// Overwrite output files instead of the default unique-append behavior
    #[arg(long)]
    overwrite: bool,

    /// Maximum requests per second (default: 300)
    #[arg(short = 't', long, default_value = "300")]
    rps: u32,

    /// Number of concurrent workers (default: 50)
    #[arg(short = 'c', long, default_value = "50")]
    concurrency: usize,
}

#[derive(Deserialize, Clone)]
struct ShodanResult {
    ip: String,
    ports: Vec<u16>,
    hostnames: Vec<String>,
}

fn get_user_agents() -> Vec<&'static str> {
    vec![
        // Latest Chrome versions (2024-2025)
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
        
        // Latest Firefox versions (2024-2025)
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:119.0) Gecko/20100101 Firefox/119.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:119.0) Gecko/20100101 Firefox/119.0",
        
        // Latest Safari versions
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
        
        // Latest Edge versions
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
        
        // Mobile browsers
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Linux; Android 14; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 13; SM-A536B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 13; ONEPLUS A6000) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36",
        
        // Different OS versions and architectures
        "Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
        
        // Less common but legitimate browsers
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Vivaldi/6.5.3206.63",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 OPR/105.0.0.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 OPR/105.0.0.0",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Brave/1.61.104",
        
        // Older but still common versions
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:118.0) Gecko/20100101 Firefox/118.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:117.0) Gecko/20100101 Firefox/117.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.4 Safari/605.1.15",
        
        // Mix of previous versions for better diversity
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:116.0) Gecko/20100101 Firefox/116.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:115.0) Gecko/20100101 Firefox/115.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:116.0) Gecko/20100101 Firefox/116.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:115.0) Gecko/20100101 Firefox/115.0",
        "Mozilla/5.0 (X11; Linux x86_64; rv:116.0) Gecko/20100101 Firefox/116.0",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0",
        
        // Additional diversity with different screen resolutions and languages
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 (Windows NT 10.0; Win64; x64; en-US)",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 (Windows NT 10.0; Win64; x64; en-GB)",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 (Macintosh; Intel Mac OS X 10_15_7; en-US)",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 (X11; Linux x86_64; en-US)",
        
        // Enterprise/Corporate versions
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Enterprise",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0 Enterprise",
        
        // Various user-agent patterns to increase diversity
        "Mozilla/5.0 (compatible; Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
        "Mozilla/5.0 (compatible; Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/119.0.0.0",
        "Mozilla/5.0 (compatible; X11; Linux x86_64) AppleWebKit/537.36 Chrome/118.0.0.0"
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

async fn query_shodan(
    client: &Client,
    ip: &str,
    user_agent: &str,
    verbose: bool,
    rps_limiter: Arc<Mutex<tokio::time::Interval>>,
) -> Result<ShodanResult, Box<dyn std::error::Error + Send + Sync>> {
    let url = format!("https://internetdb.shodan.io/{}", ip);
    let mut retries = 0;
    const MAX_RETRIES: u32 = 2;
    
    loop {
        // Enforce global rate limit
        {
            let mut limiter = rps_limiter.lock().await;
            limiter.tick().await;
        }
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

/// Open an output file with anew-style unique append semantics by default.
/// Returns the writable file handle and a set of already-seen lines.
fn open_output_with_anew(path: &str, overwrite: bool) -> io::Result<(File, HashSet<String>)> {
    let mut seen: HashSet<String> = HashSet::new();

    if overwrite {
        // Truncate and start fresh
        let file = File::create(path)?;
        return Ok((file, seen));
    }

    // Try to read existing lines if the file exists
    let p = std::path::Path::new(path);
    if p.exists() {
        if let Ok(existing) = File::open(p) {
            let reader = BufReader::new(existing);
            for line in reader.lines() {
                if let Ok(l) = line {
                    seen.insert(l);
                }
            }
        }
        // Append to existing file
        let file = OpenOptions::new().create(true).append(true).open(p)?;
        Ok((file, seen))
    } else {
        // Create new file
        let file = File::create(p)?;
        Ok((file, seen))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tmp_path(name: &str) -> String {
        let mut p = std::env::temp_dir();
        p.push(format!("qport_test_{}_{}.txt", name, std::process::id()));
        p.to_string_lossy().into_owned()
    }

    #[test]
    fn test_anew_append_unique() {
        let path = tmp_path("anew");
        // Seed file with two lines
        {
            let mut f = File::create(&path).expect("seed create");
            writeln!(f, "a").unwrap();
            writeln!(f, "b").unwrap();
        }

        // Open with anew behavior
        let (mut f, mut seen) = open_output_with_anew(&path, false).expect("open anew");

        // Attempt to add duplicate and new line
        let l1 = "a".to_string();
        let l2 = "c".to_string();
        if seen.insert(l1.clone()) { writeln!(f, "{}", l1).unwrap(); }
        if seen.insert(l2.clone()) { writeln!(f, "{}", l2).unwrap(); }
        drop(f);

        let contents = fs::read_to_string(&path).unwrap();
        let mut lines: Vec<_> = contents.lines().collect();
        lines.sort();
        assert_eq!(lines, vec!["a", "b", "c"]);

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_overwrite_truncates() {
        let path = tmp_path("overwrite");
        {
            let mut f = File::create(&path).expect("seed create");
            writeln!(f, "old").unwrap();
        }
        let (mut f, mut seen) = open_output_with_anew(&path, true).expect("open overwrite");
        let l = "new".to_string();
        if seen.insert(l.clone()) { writeln!(f, "{}", l).unwrap(); }
        drop(f);

        let contents = std::fs::read_to_string(&path).unwrap();
        assert_eq!(contents.trim(), "new");
        let _ = std::fs::remove_file(&path);
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

    // Global request rate limiter (configurable via --rps)
    let mut rate_limiter = interval(Duration::from_nanos(1_000_000_000 / args.rps as u64));
    rate_limiter.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let rps_limiter = Arc::new(Mutex::new(rate_limiter));

    let mut processed_hosts = 0;
    let mut successful_queries = 0;
    let mut failed_queries = 0;
    let mut all_results = HashMap::new();
    let request_count = Arc::new(Mutex::new(0usize));

    // Create progress bar
    let progress = ProgressBar::new(num_hosts as u64);
    progress.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} hosts ({percent}%) {msg}")
            .unwrap()
            .progress_chars("#>-")
    );

    // Collect all hosts first
    let mut hosts = Vec::new();
    for line in reader.lines() {
        let line = line?;
        let host = line.trim().to_string();
        if !host.is_empty() {
            hosts.push(host);
        }
    }

    // Simple concurrent approach using semaphore
    let semaphore = Arc::new(Semaphore::new(args.concurrency));
    let processed_count = Arc::new(Mutex::new(0usize));
    let mut join_handles = Vec::new();
    
    for host in hosts {
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        let client_clone = client.clone();
        let user_agents_clone = user_agents.clone();
        let rps_limiter_clone = rps_limiter.clone();
        let request_count_clone = request_count.clone();
        let args_verbose = args.verbose;
        let args_debug = args.debug;
        let progress_clone = progress.clone();
        let processed_count_clone = processed_count.clone();
        
        let handle = tokio::spawn(async move {
            let _permit = permit; // Keep permit until task completes
            
            // Resolve host to IPs
            let ips = resolve_host(&host).await;
            let mut host_results = vec![];
            let mut host_success_count = 0;
            let mut host_fail_count = 0;

            for ip in ips {
                // Rotate user agents for each request
                let user_agent = {
                    let mut count = request_count_clone.lock().await;
                    let ua = user_agents_clone[*count % user_agents_clone.len()];
                    *count += 1;
                    ua
                };
                
                match query_shodan(&client_clone, &ip, user_agent, args_verbose, rps_limiter_clone.clone()).await {
                    Ok(result) => {
                        let ports_count = result.ports.len();
                        host_results.push((ip.clone(), result.ports));
                        host_success_count += 1;
                        if args_debug {
                            println!("✓ {}: {} ports found", ip, ports_count);
                        }
                    }
                    Err(e) => {
                        host_fail_count += 1;
                        if args_verbose {
                            eprintln!("✗ Error querying {}: {}", ip, e);
                        }
                    }
                }
            }
            
            // Update progress
            {
                let mut count = processed_count_clone.lock().await;
                *count += 1;
                progress_clone.set_position(*count as u64);
                progress_clone.set_message(format!("Processing: {}", host));
            }

            (host, host_results, host_success_count, host_fail_count)
        });
        join_handles.push(handle);
    }
    
    // Collect results
    for handle in join_handles {
        match handle.await {
            Ok((host, host_results, host_success_count, host_fail_count)) => {
                all_results.insert(host.clone(), host_results);
                successful_queries += host_success_count;
                failed_queries += host_fail_count;
                processed_hosts += 1;
                
                if args.debug && (host_success_count > 0 || host_fail_count > 0) {
                    println!("Host {}: {} success, {} failed", host, host_success_count, host_fail_count);
                }
            }
            Err(e) => {
                if args.verbose {
                    eprintln!("Task failed: {}", e);
                }
            }
        }
    }

    // Finish progress bar
    progress.finish_with_message("Scanning complete!");

    let mut total_ports = 0;
    let mut unique_ports = 0;

    // Main output file with anew-style behavior
    let (mut output_file, mut seen_main) = open_output_with_anew(&output_filename, args.overwrite)?;

    // Optional unique file (excluding 80,443) with same behavior
    let (mut unique_output_file, mut seen_uniq) = if let Some(unique_filename) = &args.uniq {
        let (f, s) = open_output_with_anew(unique_filename, args.overwrite)?;
        (Some(f), Some(s))
    } else {
        (None, None)
    };

    for (host, ip_ports) in &all_results {
        for (ip, ports) in ip_ports {
            for port in ports {
                let result_line = format!("{}:{}", ip, port);
                if seen_main.insert(result_line.clone()) {
                    writeln!(output_file, "{}", result_line)?;
                }
                if !args.silent {
                    println!("{}", result_line);
                }
                total_ports += 1;

                // Write to unique output file if enabled and port is not 80 or 443
                if let (Some(ref mut unique_file), Some(ref mut seen_u)) = (&mut unique_output_file, &mut seen_uniq) {
                    if *port != 80 && *port != 443 {
                        if seen_u.insert(result_line.clone()) {
                            writeln!(unique_file, "{}", result_line)?;
                            unique_ports += 1;
                        }
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

