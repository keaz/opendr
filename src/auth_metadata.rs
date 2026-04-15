use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use log::{debug, error, warn};
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::{MissedTickBehavior, interval};

use crate::backend::{
    AuthenticationMetadataUpdate, AuthenticationOutcome, BackendError, DirectoryBackend,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMetadataUpdateMode {
    Sync,
    AsyncCoalesced,
    Disabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMetadataOverflowPolicy {
    FallbackSync,
    Block,
    DropWithMetric,
}

#[derive(Debug, Clone)]
pub struct AuthMetadataConfig {
    pub update_mode: AuthMetadataUpdateMode,
    pub queue_capacity: usize,
    pub flush_interval: Duration,
    pub batch_size: usize,
    pub overflow_policy: AuthMetadataOverflowPolicy,
}

impl Default for AuthMetadataConfig {
    fn default() -> Self {
        Self {
            update_mode: AuthMetadataUpdateMode::Sync,
            queue_capacity: 100_000,
            flush_interval: Duration::from_millis(100),
            batch_size: 1_000,
            overflow_policy: AuthMetadataOverflowPolicy::FallbackSync,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AuthMetadataStats {
    pub enqueued: u64,
    pub written: u64,
    pub disabled: u64,
    pub dropped: u64,
    pub fallback_sync: u64,
    pub failed: u64,
}

#[derive(Default)]
struct AuthMetadataAtomicStats {
    enqueued: AtomicU64,
    written: AtomicU64,
    disabled: AtomicU64,
    dropped: AtomicU64,
    fallback_sync: AtomicU64,
    failed: AtomicU64,
}

impl AuthMetadataAtomicStats {
    fn snapshot(&self) -> AuthMetadataStats {
        AuthMetadataStats {
            enqueued: self.enqueued.load(Ordering::Relaxed),
            written: self.written.load(Ordering::Relaxed),
            disabled: self.disabled.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
            fallback_sync: self.fallback_sync.load(Ordering::Relaxed),
            failed: self.failed.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug)]
enum AuthMetadataCommand {
    Event(AuthenticationMetadataUpdate),
    Flush(oneshot::Sender<()>),
    Shutdown(oneshot::Sender<()>),
}

#[derive(Clone)]
pub struct AuthMetadataRecorder {
    inner: Arc<AuthMetadataRecorderInner>,
}

impl fmt::Debug for AuthMetadataRecorder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthMetadataRecorder")
            .field("stats", &self.stats())
            .finish_non_exhaustive()
    }
}

enum AuthMetadataRecorderInner {
    Sync {
        backend: Arc<dyn DirectoryBackend>,
        stats: Arc<AuthMetadataAtomicStats>,
    },
    Async {
        backend: Arc<dyn DirectoryBackend>,
        sender: mpsc::Sender<AuthMetadataCommand>,
        handle: Arc<Mutex<Option<JoinHandle<()>>>>,
        stats: Arc<AuthMetadataAtomicStats>,
        overflow_policy: AuthMetadataOverflowPolicy,
    },
    Disabled {
        stats: Arc<AuthMetadataAtomicStats>,
    },
}

impl AuthMetadataRecorder {
    pub fn new(backend: Arc<dyn DirectoryBackend>, config: AuthMetadataConfig) -> Self {
        match config.update_mode {
            AuthMetadataUpdateMode::Sync => Self {
                inner: Arc::new(AuthMetadataRecorderInner::Sync {
                    backend,
                    stats: Arc::new(AuthMetadataAtomicStats::default()),
                }),
            },
            AuthMetadataUpdateMode::AsyncCoalesced => {
                let capacity = config.queue_capacity.max(1);
                let batch_size = config.batch_size.max(1);
                let flush_interval = if config.flush_interval.is_zero() {
                    Duration::from_millis(100)
                } else {
                    config.flush_interval
                };
                let (sender, receiver) = mpsc::channel(capacity);
                let stats = Arc::new(AuthMetadataAtomicStats::default());
                let handle_stats = stats.clone();
                let handle_backend = backend.clone();
                let handle = tokio::spawn(async move {
                    run_auth_metadata_worker(
                        handle_backend,
                        receiver,
                        handle_stats,
                        batch_size,
                        flush_interval,
                    )
                    .await;
                });

                Self {
                    inner: Arc::new(AuthMetadataRecorderInner::Async {
                        backend,
                        sender,
                        handle: Arc::new(Mutex::new(Some(handle))),
                        stats,
                        overflow_policy: config.overflow_policy,
                    }),
                }
            }
            AuthMetadataUpdateMode::Disabled => Self {
                inner: Arc::new(AuthMetadataRecorderInner::Disabled {
                    stats: Arc::new(AuthMetadataAtomicStats::default()),
                }),
            },
        }
    }

    pub async fn record_success(&self, dn: &str) {
        self.record(AuthenticationOutcome::Success, dn).await;
    }

    pub async fn record_failure(&self, dn: &str) {
        self.record(AuthenticationOutcome::Failure, dn).await;
    }

    pub async fn record(&self, outcome: AuthenticationOutcome, dn: &str) {
        let update = AuthenticationMetadataUpdate::new(dn, outcome);

        match self.inner.as_ref() {
            AuthMetadataRecorderInner::Sync { backend, stats } => {
                record_sync_update(backend.as_ref(), update, stats).await;
            }
            AuthMetadataRecorderInner::Async {
                backend,
                sender,
                stats,
                overflow_policy,
                ..
            } => match sender.try_send(AuthMetadataCommand::Event(update.clone())) {
                Ok(()) => {
                    stats.enqueued.fetch_add(1, Ordering::Relaxed);
                }
                Err(mpsc::error::TrySendError::Full(command)) => match overflow_policy {
                    AuthMetadataOverflowPolicy::FallbackSync => {
                        stats.fallback_sync.fetch_add(1, Ordering::Relaxed);
                        if let AuthMetadataCommand::Event(update) = command {
                            record_sync_update(backend.as_ref(), update, stats).await;
                        }
                    }
                    AuthMetadataOverflowPolicy::Block => {
                        if sender.send(command).await.is_ok() {
                            stats.enqueued.fetch_add(1, Ordering::Relaxed);
                        } else {
                            stats.failed.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    AuthMetadataOverflowPolicy::DropWithMetric => {
                        stats.dropped.fetch_add(1, Ordering::Relaxed);
                    }
                },
                Err(mpsc::error::TrySendError::Closed(command)) => {
                    stats.fallback_sync.fetch_add(1, Ordering::Relaxed);
                    if let AuthMetadataCommand::Event(update) = command {
                        record_sync_update(backend.as_ref(), update, stats).await;
                    }
                }
            },
            AuthMetadataRecorderInner::Disabled { stats } => {
                stats.disabled.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub async fn flush(&self) {
        let AuthMetadataRecorderInner::Async { sender, .. } = self.inner.as_ref() else {
            return;
        };

        let (done_tx, done_rx) = oneshot::channel();
        if sender
            .send(AuthMetadataCommand::Flush(done_tx))
            .await
            .is_ok()
        {
            let _ = done_rx.await;
        }
    }

    pub async fn shutdown(&self) {
        let AuthMetadataRecorderInner::Async { sender, handle, .. } = self.inner.as_ref() else {
            return;
        };

        let (done_tx, done_rx) = oneshot::channel();
        if sender
            .send(AuthMetadataCommand::Shutdown(done_tx))
            .await
            .is_ok()
        {
            let _ = done_rx.await;
        }

        if let Some(handle) = handle.lock().await.take()
            && let Err(err) = handle.await
        {
            warn!("auth metadata writer task failed during shutdown: {err}");
        }
    }

    pub fn stats(&self) -> AuthMetadataStats {
        match self.inner.as_ref() {
            AuthMetadataRecorderInner::Sync { stats, .. }
            | AuthMetadataRecorderInner::Async { stats, .. }
            | AuthMetadataRecorderInner::Disabled { stats } => stats.snapshot(),
        }
    }
}

async fn record_sync_update(
    backend: &dyn DirectoryBackend,
    update: AuthenticationMetadataUpdate,
    stats: &AuthMetadataAtomicStats,
) {
    match backend
        .record_authentication_updates(std::slice::from_ref(&update))
        .await
    {
        Ok(written) => {
            stats.written.fetch_add(written as u64, Ordering::Relaxed);
        }
        Err(err) => {
            stats.failed.fetch_add(1, Ordering::Relaxed);
            log_auth_metadata_error(update.dn.as_str(), update.outcome, &err);
        }
    }
}

async fn run_auth_metadata_worker(
    backend: Arc<dyn DirectoryBackend>,
    mut receiver: mpsc::Receiver<AuthMetadataCommand>,
    stats: Arc<AuthMetadataAtomicStats>,
    batch_size: usize,
    flush_interval: Duration,
) {
    let mut pending = Vec::with_capacity(batch_size);
    let mut ticker = interval(flush_interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            command = receiver.recv() => {
                match command {
                    Some(AuthMetadataCommand::Event(update)) => {
                        pending.push(update);
                        if pending.len() >= batch_size {
                            flush_pending_updates(backend.as_ref(), &mut pending, &stats).await;
                        }
                    }
                    Some(AuthMetadataCommand::Flush(done)) => {
                        flush_pending_updates(backend.as_ref(), &mut pending, &stats).await;
                        let _ = done.send(());
                    }
                    Some(AuthMetadataCommand::Shutdown(done)) => {
                        drain_available_events(&mut receiver, &mut pending);
                        flush_pending_updates(backend.as_ref(), &mut pending, &stats).await;
                        let _ = done.send(());
                        break;
                    }
                    None => {
                        flush_pending_updates(backend.as_ref(), &mut pending, &stats).await;
                        break;
                    }
                }
            }
            _ = ticker.tick() => {
                flush_pending_updates(backend.as_ref(), &mut pending, &stats).await;
            }
        }
    }

    debug!("auth metadata writer stopped");
}

fn drain_available_events(
    receiver: &mut mpsc::Receiver<AuthMetadataCommand>,
    pending: &mut Vec<AuthenticationMetadataUpdate>,
) {
    loop {
        match receiver.try_recv() {
            Ok(AuthMetadataCommand::Event(update)) => pending.push(update),
            Ok(AuthMetadataCommand::Flush(done)) | Ok(AuthMetadataCommand::Shutdown(done)) => {
                let _ = done.send(());
            }
            Err(mpsc::error::TryRecvError::Empty | mpsc::error::TryRecvError::Disconnected) => {
                break;
            }
        }
    }
}

async fn flush_pending_updates(
    backend: &dyn DirectoryBackend,
    pending: &mut Vec<AuthenticationMetadataUpdate>,
    stats: &AuthMetadataAtomicStats,
) {
    if pending.is_empty() {
        return;
    }

    match backend.record_authentication_updates(pending).await {
        Ok(written) => {
            stats.written.fetch_add(written as u64, Ordering::Relaxed);
        }
        Err(err) => {
            stats
                .failed
                .fetch_add(pending.len() as u64, Ordering::Relaxed);
            if let Some(first) = pending.first() {
                log_auth_metadata_error(first.dn.as_str(), first.outcome, &err);
            } else {
                error!("failed to write auth metadata batch: {err}");
            }
        }
    }

    pending.clear();
}

fn log_auth_metadata_error(dn: &str, outcome: AuthenticationOutcome, err: &BackendError) {
    error!("failed to write {outcome:?} account authentication metadata for {dn}: {err}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{DirectoryBackend, DirectoryEntry, MockBackend};
    use std::collections::HashMap;

    async fn backend_with_user() -> Arc<MockBackend> {
        let backend = Arc::new(MockBackend::new());
        backend
            .add_entry(
                DirectoryEntry::new(
                    "cn=user,dc=example,dc=org",
                    HashMap::from([("objectClass".to_string(), vec!["person".to_string()])]),
                ),
                b"secret".to_vec(),
            )
            .await
            .unwrap();
        backend
    }

    #[tokio::test]
    async fn sync_recorder_writes_immediately() {
        let backend = backend_with_user().await;
        let recorder = AuthMetadataRecorder::new(backend.clone(), AuthMetadataConfig::default());

        recorder.record_success("cn=user,dc=example,dc=org").await;

        let entry = backend
            .get_entry("cn=user,dc=example,dc=org")
            .await
            .unwrap()
            .unwrap();
        assert!(entry.operational_attributes.last_successful_login.is_some());
        assert_eq!(entry.operational_attributes.failed_login_count, Some(0));
        assert_eq!(recorder.stats().written, 1);
    }

    #[tokio::test]
    async fn disabled_recorder_does_not_write() {
        let backend = backend_with_user().await;
        let config = AuthMetadataConfig {
            update_mode: AuthMetadataUpdateMode::Disabled,
            ..AuthMetadataConfig::default()
        };
        let recorder = AuthMetadataRecorder::new(backend.clone(), config);

        recorder.record_failure("cn=user,dc=example,dc=org").await;

        let entry = backend
            .get_entry("cn=user,dc=example,dc=org")
            .await
            .unwrap()
            .unwrap();
        assert!(entry.operational_attributes.last_failed_login.is_none());
        assert_eq!(entry.operational_attributes.failed_login_count, None);
        assert_eq!(recorder.stats().disabled, 1);
    }

    #[tokio::test]
    async fn async_recorder_flushes_queued_events() {
        let backend = backend_with_user().await;
        let config = AuthMetadataConfig {
            update_mode: AuthMetadataUpdateMode::AsyncCoalesced,
            queue_capacity: 16,
            flush_interval: Duration::from_secs(60),
            batch_size: 8,
            overflow_policy: AuthMetadataOverflowPolicy::FallbackSync,
        };
        let recorder = AuthMetadataRecorder::new(backend.clone(), config);

        recorder.record_failure("cn=user,dc=example,dc=org").await;
        recorder.flush().await;

        let entry = backend
            .get_entry("cn=user,dc=example,dc=org")
            .await
            .unwrap()
            .unwrap();
        assert!(entry.operational_attributes.last_failed_login.is_some());
        assert_eq!(entry.operational_attributes.failed_login_count, Some(1));
        assert_eq!(recorder.stats().enqueued, 1);
        assert_eq!(recorder.stats().written, 1);

        recorder.shutdown().await;
    }

    #[tokio::test]
    async fn async_recorder_shutdown_drains_events() {
        let backend = backend_with_user().await;
        let config = AuthMetadataConfig {
            update_mode: AuthMetadataUpdateMode::AsyncCoalesced,
            queue_capacity: 16,
            flush_interval: Duration::from_secs(60),
            batch_size: 16,
            overflow_policy: AuthMetadataOverflowPolicy::FallbackSync,
        };
        let recorder = AuthMetadataRecorder::new(backend.clone(), config);

        recorder.record_failure("cn=user,dc=example,dc=org").await;
        recorder.record_success("cn=user,dc=example,dc=org").await;
        recorder.shutdown().await;

        let entry = backend
            .get_entry("cn=user,dc=example,dc=org")
            .await
            .unwrap()
            .unwrap();
        assert!(entry.operational_attributes.last_successful_login.is_some());
        assert_eq!(entry.operational_attributes.failed_login_count, Some(0));
        assert!(recorder.stats().written >= 1);
    }
}
