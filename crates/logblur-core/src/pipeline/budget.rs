//! Memory budget: keeps the number of in-flight bytes (read but not yet written) under a limit.
//! The reader acquires in entry order and the writer releases in order, so it cannot deadlock.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Condvar, Mutex};
use std::time::Duration;

pub struct Budget {
    total: u64,
    used: Mutex<u64>,
    cv: Condvar,
    high: AtomicU64,
}

impl Budget {
    pub fn new(total: u64) -> Budget {
        Budget { total: total.max(1), used: Mutex::new(0), cv: Condvar::new(), high: AtomicU64::new(0) }
    }

    pub fn total(&self) -> u64 {
        self.total
    }

    /// Acquires `n` bytes (capped at the total). Gives up and returns `None` when `stop()` is true.
    pub fn acquire(&self, n: u64, stop: &dyn Fn() -> bool) -> Option<u64> {
        let n = n.min(self.total);
        if n == 0 {
            return Some(0);
        }
        let mut used = self.used.lock().unwrap_or_else(|e| e.into_inner());
        while *used + n > self.total {
            if stop() {
                return None;
            }
            used = self.cv.wait_timeout(used, Duration::from_millis(50)).unwrap_or_else(|e| e.into_inner()).0;
        }
        *used += n;
        self.high.fetch_max(*used, Ordering::Relaxed);
        Some(n)
    }

    pub fn release(&self, n: u64) {
        if n == 0 {
            return;
        }
        let mut used = self.used.lock().unwrap_or_else(|e| e.into_inner());
        *used = used.saturating_sub(n);
        self.cv.notify_all();
    }

    pub fn high_water(&self) -> u64 {
        self.high.load(Ordering::Relaxed)
    }

    pub fn in_use(&self) -> u64 {
        *self.used.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn blocks_until_released() {
        let b = Arc::new(Budget::new(100));
        assert_eq!(b.acquire(60, &|| false), Some(60));
        let b2 = b.clone();
        let t = std::thread::spawn(move || b2.acquire(60, &|| false));
        std::thread::sleep(Duration::from_millis(100));
        b.release(60);
        assert_eq!(t.join().unwrap(), Some(60));
        assert_eq!(b.in_use(), 60);
        assert!(b.high_water() <= 100);
    }

    #[test]
    fn stop_unblocks() {
        let b = Budget::new(10);
        assert_eq!(b.acquire(10, &|| false), Some(10));
        assert_eq!(b.acquire(5, &|| true), None);
        assert_eq!(b.in_use(), 10);
    }
}
