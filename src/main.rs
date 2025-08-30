use clap::Parser;
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio::task;

#[derive(Parser)]
#[command(name = "qport")]
#[command(about = "Fast passive port scanner using Shodan InternetDB")]
struct Args {
    /// Input file with list of hosts (one per line)
    #[arg(short, long)]
    input: String,

    /// Output file for results
    #[arg(short, long)]
    output: String,

    /// Enable verbose output
    #[arg(short, long)]
    verbose: bool,

    /// Number of concurrent requests (auto-calculated based on input if not specified)
    #[arg(short, long)]
    concurrency: Option<usize>,
}

#[derive(Deserialize, Clone)]
struct ShodanResult {
    ip: String,
    ports: Vec<u16>,
    hostnames: Vec<String>,
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

async fn query_shodan(client: &Client, ip: &str, verbose: bool) -> Result<ShodanResult, Box<dyn std::error::Error + Send + Sync>> {
    let url = format!("https://internetdb.shodan.io/{}", ip);
    if verbose {
        println!("Querying: {}", url);
    }
    let resp = client.get(&url).send().await?;
    if resp.status().is_success() {
        let result: ShodanResult = resp.json().await?;
        Ok(result)
    } else {
        Err(format!("HTTP {} for {}", resp.status(), ip).into())
    }
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let args = Args::parse();

    let num_hosts = {
        let file = File::open(&args.input)?;
        let reader = BufReader::new(file);
        reader.lines().count()
    };

    let calculated_c = ((num_hosts as f64 * 0.6 / 60.0).ceil() as usize).max(1).min(10000);
    let concurrency = args.concurrency.unwrap_or(calculated_c).min(10000);

    if let Some(c) = args.concurrency {
        if c > 10000 && args.verbose {
            eprintln!("Warning: Concurrency capped at 10000.");
        }
    }

    println!("Input has {} hosts, using concurrency: {}", num_hosts, concurrency);

    configure_system(args.verbose)?;

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("Failed to build HTTP client");
    let client = Arc::new(client);

    let file = File::open(&args.input)?;
    let reader = BufReader::new(file);
    let mut tasks = vec![];
    let semaphore = Arc::new(Semaphore::new(concurrency));

    for line in reader.lines() {
        let line = line?;
        let host = line.trim().to_string();
        if host.is_empty() {
            continue;
        }
        let client_clone = Arc::clone(&client);
        let semaphore_clone = Arc::clone(&semaphore);
        let verbose = args.verbose;
        let task = task::spawn(async move {
            let _permit = semaphore_clone.acquire().await.unwrap();
            let ips = resolve_host(&host).await;
            let mut results = vec![];
            for ip in ips {
                match query_shodan(&client_clone, &ip, verbose).await {
                    Ok(result) => {
                        results.push((ip, result.ports));
                    }
                    Err(e) => {
                        if verbose {
                            eprintln!("Error querying {}: {}", ip, e);
                        }
                    }
                }
            }
            (host, results)
        });
        tasks.push(task);
    }

    let mut all_results = HashMap::new();
    for task in tasks {
        if let Ok((host, results)) = task.await {
            all_results.insert(host, results);
        }
    }

    let mut output_file = File::create(&args.output)?;
    for (host, ip_ports) in all_results {
        for (ip, ports) in ip_ports {
            for port in &ports {
                writeln!(output_file, "{}:{}", host, port)?;
            }
        }
    }

    Ok(())
}
