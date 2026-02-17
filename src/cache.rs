use ed25519_dalek::VerifyingKey;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// A single cache entry holding a verifying key and its expiry time.
struct CacheEntry {
    key: VerifyingKey,
    expires_at: Instant,
}

/// Thread-safe, in-memory TTL cache for agent public keys.
#[derive(Clone)]
pub struct KeyCache {
    store: Arc<RwLock<HashMap<String, CacheEntry>>>,
    ttl: Duration,
}

impl KeyCache {
    /// Create a new cache with the given TTL in seconds.
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            store: Arc::new(RwLock::new(HashMap::new())),
            ttl: Duration::from_secs(ttl_secs),
        }
    }

    /// Create a new cache with the default TTL of 3600 seconds (1 hour).
    pub fn default_ttl() -> Self {
        Self::new(3600)
    }

    /// Get a cached verifying key for the given DID, if present and not expired.
    pub async fn get(&self, did: &str) -> Option<VerifyingKey> {
        let store = self.store.read().await;
        if let Some(entry) = store.get(did) {
            if Instant::now() < entry.expires_at {
                return Some(entry.key);
            }
        }
        None
    }

    /// Insert or update a verifying key in the cache.
    pub async fn set(&self, did: &str, key: VerifyingKey) {
        let mut store = self.store.write().await;
        store.insert(
            did.to_string(),
            CacheEntry {
                key,
                expires_at: Instant::now() + self.ttl,
            },
        );
    }

    /// Remove expired entries from the cache.
    pub async fn evict_expired(&self) {
        let mut store = self.store.write().await;
        let now = Instant::now();
        store.retain(|_, entry| entry.expires_at > now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::generate_keypair;

    #[tokio::test]
    async fn test_cache_set_get() {
        let cache = KeyCache::default_ttl();
        let (_, verifying) = generate_keypair();
        cache.set("did:agent:test:agt_0000000000", verifying).await;
        let result = cache.get("did:agent:test:agt_0000000000").await;
        assert!(result.is_some());
        assert_eq!(result.unwrap().to_bytes(), verifying.to_bytes());
    }

    #[tokio::test]
    async fn test_cache_miss() {
        let cache = KeyCache::default_ttl();
        let result = cache.get("did:agent:test:agt_missing000").await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_cache_expired() {
        let cache = KeyCache::new(0); // 0-second TTL
        let (_, verifying) = generate_keypair();
        cache.set("did:agent:test:agt_0000000000", verifying).await;
        // Entry should be expired immediately
        std::thread::sleep(std::time::Duration::from_millis(10));
        let result = cache.get("did:agent:test:agt_0000000000").await;
        assert!(result.is_none());
    }
}
