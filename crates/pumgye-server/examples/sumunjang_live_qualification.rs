//! Owned actual Sumunjang process fixture; management uses its isolated HTTP adapter.
use anyhow::{Result, ensure};
use pumgye_server::network_live::Client;
use std::time::{SystemTime, UNIX_EPOCH};
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}
#[tokio::main(worker_threads = 2)]
async fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    ensure!(
        args.len() == 5,
        "owned fixture requires address, management and TLS files"
    );
    ensure!(
        args[1].starts_with("http://127.0.0.1:"),
        "isolated management required"
    );
    let ca = std::fs::read(&args[2])?;
    let certificate = std::fs::read(&args[3])?;
    let key = std::fs::read(&args[4])?;
    let collector = std::env::var("HANGANG_GUARD_COLLECTOR_TOKEN")?;
    let admin = std::env::var("HANGANG_GUARD_ADMIN_TOKEN")?;
    let address = format!("https://{}", args[0]);
    let client = Client::connect(
        &address,
        "sumunjang.example.test",
        &ca,
        &certificate,
        &key,
        &collector,
    )
    .await
    .map_err(|_| anyhow::anyhow!("native connection refused"))?;
    let blocked = "192.0.2.1".parse()?;
    let clear = "192.0.2.2".parse()?;
    ensure!(
        client.check(blocked, 1, &now).await.is_err(),
        "blocked IP accepted"
    );
    let first = client
        .check(clear, 1, &now)
        .await
        .map_err(|_| anyhow::anyhow!("native Allow refused"))?;
    ensure!(first.valid_at(clear, now()), "fresh observation refused");
    ensure!(!first.valid_at(blocked, now()), "IP binding lost");
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build()?;
    http.delete(format!("{}/v1/blocks", args[1]))
        .bearer_auth(&admin)
        .json(&serde_json::json!({"network":"192.0.2.1/32"}))
        .send()
        .await?
        .error_for_status()?;
    let restored = client
        .check(blocked, first.revision(), &now)
        .await
        .map_err(|_| anyhow::anyhow!("restored network refused"))?;
    ensure!(
        restored.revision() > first.revision() && restored.valid_at(blocked, now()),
        "new owner not observed"
    );
    ensure!(!first.valid_at(clear, now()), "old revision remained valid");
    http.post(format!("{}/v1/blocks", args[1])).bearer_auth(&admin).json(&serde_json::json!({"network":"192.0.2.1/32","expires_at":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()+600,"reason":"owned Pumgye qualification"})).send().await?.error_for_status()?;
    ensure!(
        client
            .check(blocked, restored.revision(), &now)
            .await
            .is_err(),
        "new block accepted"
    );
    ensure!(
        !restored.valid_at(blocked, now()),
        "new denial did not retire observation"
    );
    http.put(format!("{}/v1/policy", args[1]))
        .bearer_auth(&admin)
        .json(&serde_json::json!({"mode":"observe","allow":[]}))
        .send()
        .await?
        .error_for_status()?;
    ensure!(
        client.check(clear, 1, &now).await.is_err(),
        "observe granted enforced evidence"
    );
    http.put(format!("{}/v1/policy", args[1]))
        .bearer_auth(&admin)
        .json(&serde_json::json!({"mode":"enforce","allow":[]}))
        .send()
        .await?
        .error_for_status()?;
    ensure!(
        client
            .check(clear, 9_007_199_254_740_990, &now)
            .await
            .is_err(),
        "revision floor ignored"
    );
    let wrong = Client::connect(
        &address,
        "sumunjang.example.test",
        &ca,
        &certificate,
        &key,
        &admin,
    )
    .await
    .map_err(|_| anyhow::anyhow!("owned wrong-role channel refused"))?;
    ensure!(
        wrong.check(clear, 1, &now).await.is_err(),
        "administrator granted collector evidence"
    );
    if let Ok(wrong_name) = Client::connect(
        &address,
        "wrong.example.test",
        &ca,
        &certificate,
        &key,
        &collector,
    )
    .await
    {
        ensure!(
            wrong_name.check(clear, 1, &now).await.is_err(),
            "wrong TLS server admitted"
        );
    }
    println!(
        "PASS: actual Pumgye/Sumunjang persistent mTLS, Enforce Allow, IP binding, block/restoration, new-denial retirement, observe/role/name/floor refusal"
    );
    Ok(())
}
