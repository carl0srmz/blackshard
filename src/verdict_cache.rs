use chrono::{DateTime, Utc};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, RwLock};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheVerdict {
    Clean,
    Malicious,
    Suspicious,
    ScanError,
}

pub use crate::engine::AnalysisCompleteness;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VerdictCacheKey {
    pub volume_serial: u64,
    pub file_id: u64,
    pub file_size: u64,
    pub content_generation: u64,
    /// The file system's change time, 0 when it could not be read. The driver's
    /// `content_generation` misses mapped and kernel-mode writes and restarts when its stream
    /// context is rebuilt, so on its own a same-size overwrite could be served the old file's
    /// clean verdict.
    pub change_time: i64,
}

#[derive(Debug, Clone)]
pub struct CachedVerdict {
    pub verdict: CacheVerdict,
    pub risk_score: u32,
    pub confidence: u8,
    pub threat_name: Option<String>,
    pub sha256: Option<String>,
    pub file_size: u64,
    pub bytes_scanned: usize,
    pub truncated: bool,
    pub definition_generation: u64,
    pub scanned_at: DateTime<Utc>,
    pub analysis_completeness: AnalysisCompleteness,
    pub automatic_quarantine_eligible: bool,
    pub execution_block_eligible: bool,
}

impl CachedVerdict {
    pub fn is_cacheable(&self) -> bool {
        if self.verdict == CacheVerdict::ScanError {
            return false;
        }
        if self.verdict == CacheVerdict::Clean {
            // The definition generation is part of the cache key, so a clean result stays valid
            // until the databases change; no separate sidecar verdict needs to corroborate it.
            return self.analysis_completeness == AnalysisCompleteness::Complete
                && !self.truncated
                && self.sha256.is_some();
        }
        true
    }
}

pub struct VerdictCache {
    capacity: usize,
    /// Each entry carries the tick of its last use, which is also its key in `recency`.
    entries: HashMap<VerdictCacheKey, (CachedVerdict, u64)>,
    /// Keys ordered by last use, oldest first, so every operation is O(log n). This used to be a
    /// `VecDeque` searched from the front on every hit: at the 100,000 entry capacity the service
    /// uses, a cache hit cost up to 100,000 key comparisons on the file-open path.
    recency: BTreeMap<u64, VerdictCacheKey>,
    tick: u64,
}

impl VerdictCache {
    pub fn new(capacity: usize) -> Arc<RwLock<Self>> {
        Arc::new(RwLock::new(Self {
            capacity,
            entries: HashMap::with_capacity(capacity),
            recency: BTreeMap::new(),
            tick: 0,
        }))
    }

    /// Looks up a verdict by the file's full identity.
    ///
    /// There is deliberately no lookup by file ID alone. NTFS file IDs are only unique within a
    /// volume, so an ID-only match could hand a clean verdict cached for one drive to an unrelated
    /// file on another.
    pub fn get(
        &mut self,
        key: &VerdictCacheKey,
        current_definition_generation: u64,
    ) -> Option<CachedVerdict> {
        let (cached, last_used) = self.entries.get(key)?;
        let fresh = Utc::now()
            .signed_duration_since(cached.scanned_at)
            .num_hours()
            < 24
            && cached.definition_generation == current_definition_generation;
        let last_used = *last_used;
        self.recency.remove(&last_used);
        if !fresh {
            self.entries.remove(key);
            return None;
        }

        self.tick += 1;
        self.recency.insert(self.tick, key.clone());
        let entry = self.entries.get_mut(key).expect("present: looked up above");
        entry.1 = self.tick;
        Some(entry.0.clone())
    }

    pub fn insert(&mut self, key: VerdictCacheKey, verdict: CachedVerdict) -> bool {
        if !verdict.is_cacheable() {
            return false;
        }
        if let Some((_, last_used)) = self.entries.remove(&key) {
            self.recency.remove(&last_used);
        } else if self.entries.len() >= self.capacity {
            if let Some((_, oldest)) = self.recency.pop_first() {
                self.entries.remove(&oldest);
            }
        }
        self.tick += 1;
        self.recency.insert(self.tick, key.clone());
        self.entries.insert(key, (verdict, self.tick));
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clean(completeness: AnalysisCompleteness, truncated: bool) -> CachedVerdict {
        CachedVerdict {
            verdict: CacheVerdict::Clean,
            risk_score: 0,
            confidence: 90,
            threat_name: None,
            sha256: (!truncated).then(|| "00".repeat(32)),
            file_size: 1,
            bytes_scanned: 1,
            truncated,
            definition_generation: 1,
            scanned_at: Utc::now(),
            analysis_completeness: completeness,
            automatic_quarantine_eligible: false,
            execution_block_eligible: false,
        }
    }

    fn key(volume_serial: u64, file_id: u64) -> VerdictCacheKey {
        VerdictCacheKey {
            volume_serial,
            file_id,
            file_size: 3,
            content_generation: 4,
            change_time: 5,
        }
    }

    fn assert_consistent(cache: &VerdictCache) {
        assert_eq!(cache.entries.len(), cache.recency.len());
        for (key, (_, tick)) in &cache.entries {
            assert_eq!(cache.recency.get(tick), Some(key));
        }
    }

    #[test]
    fn rejects_partial_clean_and_scan_errors() {
        let cache = VerdictCache::new(4);
        let key = key(1, 2);
        let mut cache = cache.write().unwrap();
        assert!(!cache.insert(key.clone(), clean(AnalysisCompleteness::PrefixOnly, true)));

        let mut error = clean(AnalysisCompleteness::ResourceLimitReached, false);
        error.verdict = CacheVerdict::ScanError;
        error.sha256 = None;
        assert!(!cache.insert(key.clone(), error));
        assert!(cache.get(&key, 1).is_none());
    }

    #[test]
    fn accepts_complete_hashed_clean() {
        let cache = VerdictCache::new(4);
        let key = key(1, 2);
        let mut cache = cache.write().unwrap();
        assert!(cache.insert(key.clone(), clean(AnalysisCompleteness::Complete, false)));
        assert!(cache.get(&key, 1).is_some());
    }

    #[test]
    fn the_same_file_id_on_another_volume_is_not_a_hit() {
        let cache = VerdictCache::new(4);
        let mut cache = cache.write().unwrap();
        assert!(cache.insert(key(10, 200), clean(AnalysisCompleteness::Complete, false)));

        // A clean verdict for C: must never be handed to an unrelated file on a removable drive
        // that happens to have the same MFT record number.
        assert!(cache.get(&key(11, 200), 1).is_none());
        assert!(cache.get(&key(10, 200), 1).is_some());
    }

    #[test]
    fn a_rewritten_file_is_not_a_hit() {
        let cache = VerdictCache::new(4);
        let mut cache = cache.write().unwrap();
        assert!(cache.insert(key(1, 2), clean(AnalysisCompleteness::Complete, false)));

        // Same file, same size, same driver generation: a mapped write the driver never saw.
        let rewritten = VerdictCacheKey {
            change_time: key(1, 2).change_time + 1,
            ..key(1, 2)
        };
        assert!(cache.get(&rewritten, 1).is_none());
        assert!(cache.get(&key(1, 2), 1).is_some());
    }

    #[test]
    fn eviction_drops_the_least_recently_used_entry() {
        let cache = VerdictCache::new(2);
        let mut cache = cache.write().unwrap();
        assert!(cache.insert(key(1, 1), clean(AnalysisCompleteness::Complete, false)));
        assert!(cache.insert(key(1, 2), clean(AnalysisCompleteness::Complete, false)));

        // Reading the first entry makes the second the oldest, so it is the one evicted.
        assert!(cache.get(&key(1, 1), 1).is_some());
        assert!(cache.insert(key(1, 3), clean(AnalysisCompleteness::Complete, false)));

        assert!(cache.get(&key(1, 1), 1).is_some());
        assert!(cache.get(&key(1, 2), 1).is_none());
        assert!(cache.get(&key(1, 3), 1).is_some());
        assert_consistent(&cache);
    }

    #[test]
    fn stale_and_replaced_entries_leave_no_residue() {
        let cache = VerdictCache::new(4);
        let mut cache = cache.write().unwrap();
        assert!(cache.insert(key(1, 1), clean(AnalysisCompleteness::Complete, false)));
        assert!(cache.insert(key(1, 1), clean(AnalysisCompleteness::Complete, false)));
        assert_consistent(&cache);
        assert_eq!(cache.entries.len(), 1);

        // A definition update invalidates the entry, and the lookup removes it outright.
        assert!(cache.get(&key(1, 1), 2).is_none());
        assert!(cache.entries.is_empty() && cache.recency.is_empty());
    }

    #[test]
    fn a_full_cache_stays_at_capacity() {
        let cache = VerdictCache::new(100);
        let mut cache = cache.write().unwrap();
        for file_id in 0..1_000 {
            assert!(cache.insert(
                key(1, file_id),
                clean(AnalysisCompleteness::Complete, false)
            ));
            if file_id % 3 == 0 {
                let _ = cache.get(&key(1, file_id / 2), 1);
            }
        }
        assert_eq!(cache.entries.len(), 100);
        assert_consistent(&cache);
    }
}
