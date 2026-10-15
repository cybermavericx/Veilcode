//! One background thread plus `std::sync::mpsc`: Argon2 and file I/O never
//! run on the UI thread. The state layer only sees the `Runner` trait, so
//! tests run every job inline and synchronously.

use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};

/// A unit of background work.
pub type Job<T> = Box<dyn FnOnce() -> T + Send>;

/// The worker thread is gone (it panicked); its job's result is lost.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkerGone;

/// Runs jobs one at a time and hands back their results in order.
pub trait Runner<T> {
    /// Queues `job`.
    fn submit(&mut self, job: Job<T>) -> Result<(), WorkerGone>;
    /// A finished job's result, if one is ready. Never blocks.
    fn try_take(&mut self) -> Option<Result<T, WorkerGone>>;
}

/// The production runner: a single named background thread.
pub struct ThreadRunner<T> {
    jobs: Sender<Job<T>>,
    results: Receiver<T>,
}

impl<T: Send + 'static> ThreadRunner<T> {
    /// Starts the worker thread. `wake` is called after each finished job
    /// (the app uses it to request a repaint).
    pub fn start(wake: impl Fn() + Send + 'static) -> std::io::Result<Self> {
        let (jobs, job_rx) = mpsc::channel::<Job<T>>();
        let (result_tx, results) = mpsc::channel();
        std::thread::Builder::new()
            .name("veilcode-worker".to_string())
            .spawn(move || {
                for job in job_rx {
                    if result_tx.send(job()).is_err() {
                        break;
                    }
                    wake();
                }
            })?;
        Ok(ThreadRunner { jobs, results })
    }
}

impl<T> Runner<T> for ThreadRunner<T> {
    fn submit(&mut self, job: Job<T>) -> Result<(), WorkerGone> {
        self.jobs.send(job).map_err(|_| WorkerGone)
    }

    fn try_take(&mut self) -> Option<Result<T, WorkerGone>> {
        match self.results.try_recv() {
            Ok(t) => Some(Ok(t)),
            Err(TryRecvError::Empty) => None,
            Err(TryRecvError::Disconnected) => Some(Err(WorkerGone)),
        }
    }
}

/// Test runner: runs each job at once on the calling thread.
#[cfg(test)]
pub struct InlineRunner<T>(std::collections::VecDeque<T>);

#[cfg(test)]
impl<T> Default for InlineRunner<T> {
    fn default() -> Self {
        InlineRunner(std::collections::VecDeque::new())
    }
}

#[cfg(test)]
impl<T> Runner<T> for InlineRunner<T> {
    fn submit(&mut self, job: Job<T>) -> Result<(), WorkerGone> {
        self.0.push_back(job());
        Ok(())
    }

    fn try_take(&mut self) -> Option<Result<T, WorkerGone>> {
        self.0.pop_front().map(Ok)
    }
}

/// Test runner whose jobs run only when the test calls `finish` (a slow
/// worker), and which can be stopped (a dead worker). Clones share state.
#[cfg(test)]
pub struct Deferred<T>(std::rc::Rc<std::cell::RefCell<DeferredInner<T>>>);

#[cfg(test)]
struct DeferredInner<T> {
    jobs: std::collections::VecDeque<Job<T>>,
    done: std::collections::VecDeque<T>,
    stopped: bool,
}

#[cfg(test)]
impl<T> Clone for Deferred<T> {
    fn clone(&self) -> Self {
        Deferred(self.0.clone())
    }
}

#[cfg(test)]
impl<T> Deferred<T> {
    pub fn new() -> Self {
        Deferred(std::rc::Rc::new(std::cell::RefCell::new(DeferredInner {
            jobs: Default::default(),
            done: Default::default(),
            stopped: false,
        })))
    }

    /// Runs every queued job now.
    pub fn finish(&self) {
        loop {
            let job = self.0.borrow_mut().jobs.pop_front();
            let Some(job) = job else { break };
            let result = job();
            self.0.borrow_mut().done.push_back(result);
        }
    }

    /// The worker dies: queued jobs (and any vault in them) are dropped.
    pub fn stop(&self) {
        let jobs = {
            let mut inner = self.0.borrow_mut();
            inner.stopped = true;
            std::mem::take(&mut inner.jobs)
        };
        drop(jobs);
    }
}

#[cfg(test)]
impl<T> Runner<T> for Deferred<T> {
    fn submit(&mut self, job: Job<T>) -> Result<(), WorkerGone> {
        let mut inner = self.0.borrow_mut();
        if inner.stopped {
            return Err(WorkerGone);
        }
        inner.jobs.push_back(job);
        Ok(())
    }

    fn try_take(&mut self) -> Option<Result<T, WorkerGone>> {
        let mut inner = self.0.borrow_mut();
        match inner.done.pop_front() {
            Some(t) => Some(Ok(t)),
            None if inner.stopped => Some(Err(WorkerGone)),
            None => None,
        }
    }
}
