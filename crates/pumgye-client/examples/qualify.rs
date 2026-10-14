//! Owned deterministic allow fixture; results describe this transport, not the full gateway.
use anyhow::{Result, ensure};
use clap::Parser;
use pumgye_client::{Client, Tls};
use pumgye_protocol::{Decision, GuardEvidence, Query};
use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
#[derive(Parser)]
struct Args {
    #[arg(long)]
    address: SocketAddr,
    #[arg(long)]
    ca: Option<PathBuf>,
    #[arg(long)]
    cert: Option<PathBuf>,
    #[arg(long)]
    key: Option<PathBuf>,
    #[arg(long, default_value = "pumgye.example.test")]
    server_name: String,
    #[arg(long, default_value_t = 1)]
    minimum_revision: u64,
    #[arg(long, default_value_t = 10000)]
    requests: usize,
    #[arg(long, default_value_t = 0)]
    seconds: u64,
    #[arg(long, default_value_t = 16)]
    concurrency: usize,
    #[arg(long, default_value_t = 64)]
    batch: usize,
    #[arg(long, default_value_t = 0)]
    cardinality: usize,
}
#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    ensure!(
        args.requests > 0
            && (1..=64).contains(&args.batch)
            && (1..=256).contains(&args.concurrency)
            && args.cardinality <= 4096
            && (args.cardinality == 0 || args.batch == 1),
        "invalid load fixture size"
    );
    let tls = match (&args.ca, &args.cert, &args.key) {
        (Some(ca), Some(cert), Some(key)) => {
            Some(Tls::from_files(&args.server_name, ca, cert, key)?)
        }
        (None, None, None) => None,
        _ => anyhow::bail!("all client TLS paths are required together"),
    };
    let client = Arc::new(Client::new(
        args.address,
        tls,
        std::env::var("PUMGYE_DECISION_TOKEN")?,
        args.concurrency,
        Duration::from_secs(2),
        args.minimum_revision,
    )?);
    let mut jobs = tokio::task::JoinSet::new();
    let started = Instant::now();
    for worker in 0..args.concurrency {
        let client = client.clone();
        let total = args.requests / args.concurrency
            + usize::from(worker < args.requests % args.concurrency);
        let batch = args.batch;
        let cardinality = args.cardinality;
        let duration = Duration::from_secs(args.seconds);
        jobs.spawn(async move {
            let query = Query {
                request_id: 0,
                minimum_revision: 0,
                ip: "192.0.2.8".parse()?,
                aal: 1,
                guard: GuardEvidence::EnforcedAllow,
                service_id: "orders",
                subject: "fixture",
                permission: "read",
                information_class: "public",
            };
            let mut remaining = total;
            let mut completed = 0;
            let mut latencies = Vec::new();
            while remaining > 0 || started.elapsed() < duration {
                let count = if remaining == 0 {
                    batch
                } else {
                    remaining.min(batch)
                };
                let index = if cardinality > 0 {
                    (completed * 17 + worker * 131) % cardinality
                } else {
                    0
                };
                let subject = if cardinality > 0 {
                    format!("fixture-{index}")
                } else {
                    "fixture".to_owned()
                };
                let query = Query {
                    subject: &subject,
                    ip: if cardinality > 0 {
                        std::net::Ipv4Addr::new(198, 18, (index / 256) as u8, (index % 256) as u8)
                            .into()
                    } else {
                        query.ip
                    },
                    ..query
                };
                let start = Instant::now();
                let replies = if count == 1 {
                    vec![client.decide(&query).await?]
                } else {
                    client.decide_batch(&vec![query; count]).await?
                };
                ensure!(
                    replies.len() == count
                        && replies.iter().all(|r| r.decision == Some(Decision::Allow)),
                    "fixture must receive verified allow decisions"
                );
                latencies.push(start.elapsed().as_micros() as u64);
                remaining = remaining.saturating_sub(count);
                completed += count;
            }
            Ok::<_, anyhow::Error>((completed, latencies))
        });
    }
    let mut actual = 0;
    let mut latencies = Vec::new();
    while let Some(job) = jobs.join_next().await {
        let (count, mut times) = job??;
        actual += count;
        latencies.append(&mut times);
    }
    ensure!(
        (args.seconds > 0 && actual >= args.requests) || actual == args.requests,
        "request count mismatch"
    );
    let elapsed = started.elapsed().as_secs_f64();
    latencies.sort_unstable();
    println!(
        "{}",
        serde_json::json!({"transport":if args.ca.is_some(){"PPG1/mTLS"}else{"PPG1/loopback"},"requests":actual,"concurrency":args.concurrency,"batch":args.batch,"cardinality":args.cardinality,"elapsed_seconds":elapsed,"minimum_duration_seconds":args.seconds,"qps":actual as f64/elapsed,"batch_p50_us":latencies[latencies.len()/2],"batch_p99_us":latencies[(latencies.len()-1)*99/100],"revision":client.revision()})
    );
    Ok(())
}
