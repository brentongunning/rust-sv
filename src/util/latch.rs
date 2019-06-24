use crate::util::{Error, Result};
use std::fmt;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

/// A one-way latch for thread synchronization
///
/// It is similar to Java's CountdownLatch when counter is 1.
pub struct Latch {
    open: Mutex<bool>,
    condvar: Condvar,
}

impl Latch {
    /// Creates a new latch in an unopened state
    pub fn new() -> Arc<Latch> {
        Arc::new(Latch {
            open: Mutex::new(false),
            condvar: Condvar::new(),
        })
    }

    /// Opens the latch unblocking all wait and wait_timeout calls forever
    pub fn open(&self) {
        let mut open = self.open.lock().unwrap();
        *open = true;
        self.condvar.notify_one();
    }

    /// Waits until open is called
    pub fn wait(&self) {
        let mut open = self.open.lock().unwrap();
        while !*open {
            open = self.condvar.wait(open).unwrap();
        }
    }

    /// Waits until open is called, with a timeout. The result will return Error::Timeout if a timeout occurred.
    pub fn wait_timeout(&self, duration: Duration) -> Result<()> {
        let mut open = self.open.lock().unwrap();
        while !*open {
            let result = self.condvar.wait_timeout(open, duration).unwrap();
            if result.1.timed_out() {
                return Err(Error::Timeout);
            }
            open = result.0;
        }
        Ok(())
    }

    /// Returns whether the latch has been opened or not
    pub fn opened(&self) -> bool {
        *self.open.lock().unwrap()
    }
}

impl fmt::Debug for Latch {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let state = if self.opened() { "opened" } else { "closed" };
        f.write_str(&format!("Latch({})", state))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn one_thread() {
        let latch = Latch::new();
        assert!(!latch.opened());
        latch.open();
        assert!(latch.opened());
        latch.wait();
    }

    #[test]
    fn two_threads() {
        let latch = Latch::new();
        let thread_latch = latch.clone();
        thread::spawn(move || {
            assert!(!thread_latch.opened());
            thread_latch.open();
        });
        latch.wait();
        assert!(latch.opened());
    }

    #[test]
    fn opens_and_waits() {
        let latch = Latch::new();
        latch.open();
        latch.wait();
        latch.wait();
        latch.open();
        latch.wait();
        assert!(latch.opened());
    }

    #[test]
    fn timeout() {
        let latch = Latch::new();
        assert!(latch.wait_timeout(Duration::from_millis(1)).is_err());
        latch.open();
        assert!(latch.wait_timeout(Duration::from_secs(1)).is_ok());
    }
}
