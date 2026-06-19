use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

pub struct ClientMetrics {
    pub id: u64,
    pub addr: String,
    pub start_time: Instant,
    pub upload_bytes: AtomicU64,
    pub download_bytes: AtomicU64,
}

impl ClientMetrics {
    pub fn new(id: u64, addr: String) -> Self {
        Self {
            id,
            addr,
            start_time: Instant::now(),
            upload_bytes: AtomicU64::new(0),
            download_bytes: AtomicU64::new(0),
        }
    }
}

pub struct GlobalMetrics {
    pub clients: RwLock<HashMap<u64, Arc<ClientMetrics>>>,
    pub total_upload: AtomicU64,
    pub total_download: AtomicU64,
    next_id: AtomicU64,
}

impl GlobalMetrics {
    pub fn new() -> Self {
        Self {
            clients: RwLock::new(HashMap::new()),
            total_upload: AtomicU64::new(0),
            total_download: AtomicU64::new(0),
            next_id: AtomicU64::new(1),
        }
    }

    pub fn generate_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    pub async fn add_client(&self, client: Arc<ClientMetrics>) {
        self.clients.write().await.insert(client.id, client);
    }

    pub async fn remove_client(&self, id: u64) {
        self.clients.write().await.remove(&id);
    }

    pub fn add_upload(&self, bytes: u64) {
        self.total_upload.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn add_download(&self, bytes: u64) {
        self.total_download.fetch_add(bytes, Ordering::Relaxed);
    }
}

use std::sync::OnceLock;

pub fn global_metrics() -> &'static Arc<GlobalMetrics> {
    static METRICS: OnceLock<Arc<GlobalMetrics>> = OnceLock::new();
    METRICS.get_or_init(|| Arc::new(GlobalMetrics::new()))
}
