use crate::util::latch::Latch;
use std::fmt;
use std::mem::swap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// A promise for a value in the future
pub struct Future<T> {
    latch: Arc<Latch>,
    result: Arc<Mutex<Option<T>>>,
}

/// A provider for a Future's value
pub struct FutureProvider<T> {
    latch: Arc<Latch>,
    result: Arc<Mutex<Option<T>>>,
}

impl<T> Future<T> {
    /// Creates a new future and its provider
    pub fn new() -> (Future<T>, FutureProvider<T>) {
        let future = Future {
            latch: Latch::new(),
            result: Arc::new(Mutex::new(None)),
        };

        let provider = FutureProvider {
            latch: future.latch.clone(),
            result: future.result.clone(),
        };

        (future, provider)
    }

    /// Creates a future that returns a specific value
    pub fn single(value: T) -> Future<T> {
        let latch = Latch::new();
        latch.open();
        Future {
            latch,
            result: Arc::new(Mutex::new(Some(value))),
        }
    }

    /// Waits for a value and consumes the future
    pub fn get(self) -> T {
        self.latch.wait();
        let mut lock = self.result.lock().unwrap();
        let mut ret = None;
        swap(&mut ret, &mut *lock);
        ret.unwrap()
    }

    /// Waits up to a certain duration for a value and consumes the future
    pub fn get_timeout(self, duration: Duration) -> Result<T, Future<T>> {
        if let Err(_) = self.latch.wait_timeout(duration) {
            return Err(self);
        }
        let mut lock = self.result.lock().unwrap();
        let mut ret = None;
        swap(&mut ret, &mut *lock);
        Ok(ret.unwrap())
    }
}

impl<T> FutureProvider<T> {
    /// Sets a value and unblocks the Future
    pub fn put(&self, value: T) {
        let mut result = self.result.lock().unwrap();
        *result = Some(value);
        self.latch.open();
    }
}

impl<T> fmt::Debug for Future<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let state = if self.latch.opened() { "done" } else { "none" };
        f.write_str(&format!("Future({})", state))
    }
}

impl<T> fmt::Debug for FutureProvider<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let state = if self.latch.opened() { "done" } else { "none" };
        f.write_str(&format!("FutureProvider({})", state))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn across_threads() {
        let (future, provider) = Future::<u32>::new();
        thread::spawn(move || provider.put(3));
        assert!(future.get() == 3);
    }

    #[test]
    fn timeout() {
        let (future, _provider) = Future::<u32>::new();
        assert!(future.get_timeout(Duration::from_millis(10)).is_err());
    }
}
