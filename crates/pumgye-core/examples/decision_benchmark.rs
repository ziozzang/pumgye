//! Synthetic maximum-assignment core measurement; excludes compilation and transport.
use pumgye_core::{Decision, GuardEvidence, Network, Policy, Role, Service};
use std::{
    collections::BTreeMap,
    hint::black_box,
    net::{IpAddr, Ipv4Addr},
    time::Instant,
};
fn main() -> anyhow::Result<()> {
    let iterations: usize = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "1000000".into())
        .parse()?;
    anyhow::ensure!(
        (1..=100_000_000).contains(&iterations),
        "iterations must be 1..100000000"
    );
    let pattern = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "sequential".into());
    anyhow::ensure!(
        matches!(pattern.as_str(), "sequential" | "shuffled"),
        "pattern must be sequential or shuffled"
    );
    let count = 65_536usize;
    let mut order: Vec<usize> = (0..count).collect();
    if pattern == "shuffled" {
        // Deterministic Fisher-Yates fixture; random generation is outside measurement.
        let mut seed = 0x5a17_9d23_6c41_ef85u64;
        for i in (1..count).rev() {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            order.swap(i, (seed as usize) % (i + 1));
        }
    }

    let subjects: Vec<String> = (0..count).map(|i| format!("fixture_{i}")).collect();
    let addresses: Vec<IpAddr> = (0..count)
        .map(|i| IpAddr::V4(Ipv4Addr::from(0xc6120000 + i as u32)))
        .collect();
    let service = Service {
        authorization_context: Default::default(),
        workload_users: Default::default(),
        human_users: Default::default(),
        permissions: vec!["read".into()],
        roles: BTreeMap::from([(
            "reader".into(),
            Role {
                permissions: vec!["read".into()],
                information_classes: vec!["public".into()],
                inherits: vec![],
                minimum_aal: 1,
            },
        )]),
        users: subjects
            .iter()
            .map(|s| (s.clone(), vec!["reader".into()]))
            .collect(),
        networks: addresses
            .iter()
            .map(|ip| Network {
                cidr: ipnet::IpNet::new(*ip, 32).unwrap(),
                roles: vec!["reader".into()],
            })
            .collect(),
        require_guard: true,
    };
    let compiled = Policy {
        kubernetes_authorization: None,
        version: 1,
        resources: BTreeMap::new(),
        information_classes: vec!["public".into()],
        services: BTreeMap::from([("orders".into(), service)]),
    }
    .compile()?;
    // Walk every identity/prefix before timing; avoid timing construction or cold startup.
    for i in 0..count {
        anyhow::ensure!(
            compiled.evaluate(
                "orders",
                &subjects[i],
                addresses[i],
                "read",
                "public",
                1,
                GuardEvidence::EnforcedAllow
            ) == Decision::Allow,
            "fixture refused"
        );
    }
    let started = Instant::now();
    let mut allows = 0usize;
    for i in 0..iterations {
        let index = black_box(order[i % count]);
        let result = compiled.evaluate(
            black_box("orders"),
            black_box(&subjects[index]),
            black_box(addresses[index]),
            black_box("read"),
            black_box("public"),
            black_box(1),
            black_box(GuardEvidence::EnforcedAllow),
        );
        allows += usize::from(black_box(result) == Decision::Allow);
    }
    let elapsed = started.elapsed().as_secs_f64();
    anyhow::ensure!(
        allows == iterations,
        "unexpected refusal during measurement"
    );
    println!(
        "{}",
        serde_json::json!({"scope":"single-thread compiled core; warmed maximum assignments; no SQL/TLS/network", "access_pattern":pattern, "users":count,"ipv4_prefixes":count,"verified_decisions":allows,"elapsed_seconds":elapsed,"decisions_per_second":iterations as f64/elapsed,"nanoseconds_per_decision":elapsed*1e9/iterations as f64})
    );
    Ok(())
}
