//! Bounded, cancellable DNS updates for an already connected tunnel.
use std::sync::{atomic::{AtomicBool, Ordering}, Mutex};
use std::time::Duration;
use anyhow::{bail, Result};
use hickory_resolver::TokioAsyncResolver;
use tokio::task::JoinSet;

#[derive(Default)]
pub struct Preparation {
    cancelled: AtomicBool,
    message: Mutex<String>,
}

impl Preparation {
    pub fn start(&self) {
        self.cancelled.store(false, Ordering::SeqCst);
        self.report("Подключение…".into());
    }
    pub fn cancel(&self) { self.cancelled.store(true, Ordering::SeqCst); }
    pub fn check(&self) -> Result<()> {
        if self.cancelled.load(Ordering::SeqCst) { bail!("Подключение отменено"); }
        Ok(())
    }
    pub fn report(&self, message: String) { *self.message.lock().unwrap() = message; }
    pub fn message(&self) -> String { self.message.lock().unwrap().clone() }
}

pub fn known_entries(entries: &[String]) -> Vec<String> {
    crate::split::resolve_entries(entries, |_| vec![]).0
}

pub fn resolve(entries: &[String], progress: &Preparation) -> Result<(Vec<String>, Vec<String>)> {
    resolve_with(entries, progress, |_| Ok(()))
}

pub fn resolve_with(entries: &[String], progress: &Preparation, on_addresses: impl FnMut(&[String]) -> Result<()>) -> Result<(Vec<String>, Vec<String>)> {
    // Reuse the existing domain/IP parsing. The callback collects names without doing DNS.
    let domains = Mutex::new(Vec::new());
    let (mut nets, _) = crate::split::resolve_entries(entries, |host| {
        domains.lock().unwrap().push(host.to_string());
        vec![]
    });
    let mut domains = domains.into_inner().unwrap();
    domains.sort();
    domains.dedup();
    progress.check()?;
    if domains.is_empty() { return Ok((nets, vec![])); }
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let (resolved, failed) = runtime.block_on(async {
        let resolver = TokioAsyncResolver::tokio_from_system_conf()?;
        resolve_async(domains, progress, move |host| {
            let resolver = resolver.clone();
            async move {
                match tokio::time::timeout(Duration::from_secs(3), resolver.ipv4_lookup(host)).await {
                    Ok(Ok(ips)) => ips.iter().map(|ip| ip.to_string()).collect(),
                    _ => vec![],
                }
            }
        }, on_addresses).await
    })?;
    nets.extend(resolved);
    nets.sort();
    nets.dedup();
    if nets.is_empty() && !failed.is_empty() { bail!("Не удалось определить адреса сайтов. Проверьте DNS и доступ к интернету."); }
    Ok((nets, failed))
}

async fn resolve_async<F, Fut>(domains: Vec<String>, progress: &Preparation, lookup: F, mut on_addresses: impl FnMut(&[String]) -> Result<()>) -> Result<(Vec<String>, Vec<String>)>
where F: Fn(String) -> Fut, Fut: std::future::Future<Output = Vec<String>> + Send + 'static {
    let started = std::time::Instant::now();
    let total = domains.len();
    let mut pending = domains.into_iter();
    let mut jobs = JoinSet::new();
    let (mut nets, mut failed) = (vec![], vec![]);
    let mut done = 0;
    loop {
        progress.check()?;
        if started.elapsed() > Duration::from_secs(300) { bail!("Подготовка списка превысила 5 минут. Проверьте DNS или сократите список сайтов."); }
        while jobs.len() < 32 {
            let Some(host) = pending.next() else { break };
            let future = lookup(host.clone());
            jobs.spawn(async move { (host, future.await) });
        }
        progress.report(format!("Подготовка сайтов: {done} из {total}"));
        if jobs.is_empty() { break; }
        tokio::select! {
            result = jobs.join_next() => {
                let (host, ips) = result.unwrap()?;
                if ips.is_empty() { failed.push(host); } else { on_addresses(&ips)?; nets.extend(ips); }
                done += 1;
            }
            _ = tokio::time::sleep(Duration::from_millis(50)) => {}
        }
    }
    Ok((nets, failed))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "requires AMZ_DNS_TEST_FILE; performs DNS queries, does not change networking"]
    fn external_list_dns() {
        let path = std::env::var("AMZ_DNS_TEST_FILE").unwrap();
        let entries: Vec<String> = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let progress = Preparation::default();
        let start = std::time::Instant::now();
        let (nets, failed) = resolve(&entries, &progress).unwrap();
        println!("{} entries -> {} unique addresses, {} unresolved; {:.1}s; {}", entries.len(), nets.len(), failed.len(), start.elapsed().as_secs_f64(), progress.message());
        assert!(!nets.is_empty());
    }

    #[test]
    fn connection_uses_known_ips_without_resolving_domains() {
        let mut entries: Vec<String> = (0..19042).map(|i| format!("site{i}.example")).collect();
        entries.extend(["192.0.2.1".into(), "10.0.0.0/8".into(), "2001:db8::1".into()]);
        assert_eq!(known_entries(&entries), ["10.0.0.0/8", "192.0.2.1", "2001:db8::1"]);
    }

    #[test]
    fn delivers_fast_answer_without_waiting_for_slow_domain() {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let progress = Preparation::default();
        let delivered = AtomicBool::new(false);
        rt.block_on(async {
            let work = resolve_async(vec!["fast.example".into(), "slow.example".into()], &progress,
                |host| async move {
                    if host == "slow.example" { std::future::pending::<()>().await; }
                    vec!["192.0.2.1".into()]
                }, |ips| {
                    assert_eq!(ips, ["192.0.2.1"]);
                    delivered.store(true, Ordering::SeqCst);
                    Ok(())
                });
            let cancel = async {
                while !delivered.load(Ordering::SeqCst) { tokio::time::sleep(Duration::from_millis(5)).await; }
                progress.cancel();
            };
            let (result, _) = tokio::time::timeout(Duration::from_secs(1), async { tokio::join!(work, cancel) }).await.unwrap();
            assert!(result.is_err());
            assert!(delivered.load(Ordering::SeqCst));
        });
    }

    #[test]
    fn large_list_and_cancel() {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let progress = Preparation::default();
        rt.block_on(async {
            let domains = (0..19042).map(|i| format!("site{i}.example")).collect();
            let (nets, failed) = resolve_async(domains, &progress, |_| async { vec!["192.0.2.1".into()] }, |_| Ok(())).await.unwrap();
            assert_eq!(nets.len(), 19042);
            assert!(failed.is_empty());
            assert!(progress.message().contains("19042 из 19042"));
            let resolve = resolve_async(vec!["slow.example".into(); 100], &progress, |_| async {
                std::future::pending::<Vec<String>>().await
            }, |_| Ok(()));
            let cancel = async { tokio::time::sleep(Duration::from_millis(20)).await; progress.cancel(); };
            let (result, _) = tokio::join!(resolve, cancel);
            assert!(result.unwrap_err().to_string().contains("отменено"));
        });
    }
}
