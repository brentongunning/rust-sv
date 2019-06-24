//! Lightweight reactive library

use crate::util::future::{Future, FutureProvider};
use crate::util::{Error, Result};
use std::sync::{Arc, RwLock, TryLockError, Weak};
use std::time::Duration;

/// Observes an event of type T
pub trait Observer<T>: Sync + Send {
    /// Called when the event occurs
    fn next(&self, event: &T);
}

/// Event publisher that may be subscribed to
pub trait Observable<T: Send + Sync + Clone + 'static> {
    /// Adds a weakly held observer
    fn subscribe<S: Observer<T> + 'static>(&self, observer: &Arc<S>);

    /// Waits indefinitely for an event to be emitted
    fn poll(&self) -> T {
        let (poller, future) = Poller::new();
        self.subscribe(&poller);
        future.get()
    }

    /// Waits for an event to be emitted with a timeout
    fn poll_timeout(&self, duration: Duration) -> Result<T> {
        let (poller, future) = Poller::new();
        self.subscribe(&poller);
        match future.get_timeout(duration) {
            Ok(t) => Ok(t),
            Err(_future) => Err(Error::Timeout),
        }
    }
}

/// Stores the observers for a particular event
pub struct Subject<T> {
    observers: RwLock<Vec<Weak<Observer<T>>>>,
    pending: RwLock<Vec<Weak<Observer<T>>>>,
}

impl<T> Subject<T> {
    /// Creates a new empty set of observers
    pub fn new() -> Subject<T> {
        Subject {
            observers: RwLock::new(Vec::new()),
            pending: RwLock::new(Vec::new()),
        }
    }
}

impl<T> Observer<T> for Subject<T> {
    fn next(&self, event: &T) {
        let mut any_to_remove = false;

        {
            for observer in self.observers.read().unwrap().iter() {
                match observer.upgrade() {
                    Some(observer) => observer.next(event),
                    None => any_to_remove = true,
                }
            }
        }

        if any_to_remove {
            let mut observers = self.observers.write().unwrap();
            observers.retain(|observer| observer.upgrade().is_some());
        }

        let any_pending = { self.pending.read().unwrap().len() > 0 };
        if any_pending {
            let mut observers = self.observers.write().unwrap();
            let mut pending = self.pending.write().unwrap();
            observers.append(&mut pending);
        }
    }
}

impl<T: Send + Sync + Clone + 'static> Observable<T> for Subject<T> {
    fn subscribe<S: Observer<T> + 'static>(&self, observer: &Arc<S>) {
        let weak_observer = Arc::downgrade(observer) as Weak<Observer<T>>;

        match self.observers.try_write() {
            Ok(mut observers) => observers.push(weak_observer),

            // If we would block, add to a pending set
            Err(TryLockError::WouldBlock) => {
                self.pending.write().unwrap().push(weak_observer);
            }

            // If observer is poisoned, app will be killed soon
            Err(TryLockError::Poisoned(_)) => panic!("Observer lock poisoned"),
        }
    }
}

/// A subject that only emits a single value
///
/// After a value is emmitted once, all future calls to next() will be ignored,
/// and any future subscriptions will be called with the original value once.
pub struct Single<T: Sync + Send + Clone> {
    subject: Subject<T>,
    value: RwLock<Option<T>>,
}

impl<T: Sync + Send + Clone> Single<T> {
    /// Creates a new single with an empty set of observers
    pub fn new() -> Single<T> {
        Single {
            subject: Subject::new(),
            value: RwLock::new(None),
        }
    }
}

impl<T: Sync + Send + Clone> Observer<T> for Single<T> {
    fn next(&self, event: &T) {
        let mut value = self.value.write().unwrap();
        if let None = *value {
            *value = Some(event.clone());
            self.subject.next(event);
        }
    }
}

impl<T: Sync + Send + Clone + 'static> Observable<T> for Single<T> {
    fn subscribe<S: Observer<T> + 'static>(&self, observer: &Arc<S>) {
        match &*self.value.read().unwrap() {
            Some(value) => observer.next(&value),
            None => self.subject.subscribe(observer),
        }
    }
}

struct Poller<T: Sync + Send + Clone> {
    future_provider: FutureProvider<T>,
}

impl<T: Sync + Send + Clone> Poller<T> {
    pub fn new() -> (Arc<Poller<T>>, Future<T>) {
        let (future, future_provider) = Future::new();
        (Arc::new(Poller { future_provider }), future)
    }
}

impl<T: Sync + Send + Clone> Observer<T> for Poller<T> {
    fn next(&self, event: &T) {
        self.future_provider.put(event.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn publish_observe() {
        struct MyObserver {
            observed: AtomicBool,
        }

        impl<'a> Observer<u32> for MyObserver {
            fn next(&self, _event: &u32) {
                self.observed.store(true, Ordering::Relaxed);
            }
        }

        let subject = Subject::<u32>::new();
        let observer = Arc::new(MyObserver {
            observed: AtomicBool::new(false),
        });
        subject.subscribe(&observer);

        assert!(!observer.observed.load(Ordering::Relaxed));
        subject.next(&1);
        assert!(observer.observed.load(Ordering::Relaxed));
    }

    #[test]
    fn observe_during_next() {
        let subject = Arc::new(Subject::<u32>::new());
        struct MyObserver {
            subject: Arc<Subject<u32>>,
        }
        impl<'a> Observer<u32> for MyObserver {
            fn next(&self, _event: &u32) {
                self.subject.subscribe(&Arc::new(MyObserver {
                    subject: self.subject.clone(),
                }));
            }
        }
        subject.subscribe(&Arc::new(MyObserver {
            subject: subject.clone(),
        }));
        subject.next(&1);
    }

    #[test]
    fn single() {
        struct MyObserver {
            observed: AtomicBool,
        }

        impl<'a> Observer<u32> for MyObserver {
            fn next(&self, event: &u32) {
                assert!(event == &5);
                assert!(!self.observed.swap(true, Ordering::Relaxed));
            }
        }

        let pre_emit_observer = Arc::new(MyObserver {
            observed: AtomicBool::new(false),
        });

        let post_emit_observer = Arc::new(MyObserver {
            observed: AtomicBool::new(false),
        });

        let single = Single::<u32>::new();
        single.subscribe(&pre_emit_observer);
        single.next(&5);
        assert!(pre_emit_observer.observed.load(Ordering::Relaxed));
        single.subscribe(&post_emit_observer);
        assert!(post_emit_observer.observed.load(Ordering::Relaxed));
        single.next(&6);
    }
}
