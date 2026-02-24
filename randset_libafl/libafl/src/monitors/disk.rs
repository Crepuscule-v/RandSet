//! Monitors that wrap a base monitor and also log to disk using different formats like `JSON` and `TOML`.

use alloc::{string::String, vec::Vec};
use core::time::Duration;
use std::{
    fs::{File, OpenOptions},
    io::Write,
    path::PathBuf,
};

use libafl_bolts::{current_time, format_duration_hms, ClientId};
use serde_json::json;

use crate::monitors::{ClientStats, Monitor, NopMonitor};

/// Wrap a monitor and log the current state of the monitor into a Toml file.
#[derive(Debug, Clone)]
pub struct OnDiskTomlMonitor<M>
where
    M: Monitor,
{
    base: M,
    filename: PathBuf,
    last_update: Duration,
    update_interval: Duration,
}

impl<M> Monitor for OnDiskTomlMonitor<M>
where
    M: Monitor,
{
    /// The client monitor, mutable
    fn client_stats_mut(&mut self) -> &mut Vec<ClientStats> {
        self.base.client_stats_mut()
    }

    /// The client monitor
    fn client_stats(&self) -> &[ClientStats] {
        self.base.client_stats()
    }

    /// Time this fuzzing run stated
    fn start_time(&self) -> Duration {
        self.base.start_time()
    }

    /// Set creation time
    fn set_start_time(&mut self, time: Duration) {
        self.base.set_start_time(time);
    }

    fn aggregate(&mut self, name: &str) {
        self.base.aggregate(name);
    }

    fn display(&mut self, event_msg: &str, sender_id: ClientId) {
        let cur_time = current_time();

        if cur_time - self.last_update >= self.update_interval {
            self.last_update = cur_time;

            let mut file = File::create(&self.filename).expect("Failed to open the Toml file");
            write!(
                &mut file,
                "# This Toml is generated using the OnDiskMonitor component of LibAFL

[global]
run_time = \"{}\"
clients = {}
corpus = {}
objectives = {}
executions = {}
exec_sec = {}
",
                format_duration_hms(&(cur_time - self.start_time())),
                self.client_stats_count(),
                self.corpus_size(),
                self.objective_size(),
                self.total_execs(),
                self.execs_per_sec()
            )
            .expect("Failed to write to the Toml file");

            for (i, client) in self.client_stats_mut().iter_mut().enumerate() {
                let exec_sec = client.execs_per_sec(cur_time);

                write!(
                    &mut file,
                    "
[client_{}]
corpus = {}
objectives = {}
executions = {}
exec_sec = {}
",
                    i, client.corpus_size, client.objective_size, client.executions, exec_sec
                )
                .expect("Failed to write to the Toml file");

                for (key, val) in &client.user_monitor {
                    let k: String = key
                        .chars()
                        .map(|c| if c.is_whitespace() { '_' } else { c })
                        .filter(|c| c.is_alphanumeric() || *c == '_')
                        .collect();
                    writeln!(&mut file, "{k} = \"{val}\"")
                        .expect("Failed to write to the Toml file");
                }
            }

            drop(file);
        }

        self.base.display(event_msg, sender_id);
    }
}

impl<M> OnDiskTomlMonitor<M>
where
    M: Monitor,
{
    /// Create new [`OnDiskTomlMonitor`]
    #[must_use]
    pub fn new<P>(filename: P, base: M) -> Self
    where
        P: Into<PathBuf>,
    {
        Self::with_update_interval(filename, base, Duration::from_secs(60))
    }

    /// Create new [`OnDiskTomlMonitor`] with custom update interval
    #[must_use]
    pub fn with_update_interval<P>(filename: P, base: M, update_interval: Duration) -> Self
    where
        P: Into<PathBuf>,
    {
        Self {
            base,
            filename: filename.into(),
            last_update: current_time() - update_interval,
            update_interval,
        }
    }
}

impl OnDiskTomlMonitor<NopMonitor> {
    /// Create new [`OnDiskTomlMonitor`] without a base
    #[must_use]
    pub fn nop<P>(filename: P) -> Self
    where
        P: Into<PathBuf>,
    {
        Self::new(filename, NopMonitor::new())
    }
}

#[derive(Debug, Clone)]
/// Wraps a base monitor and continuously appends the current statistics to a Json lines file.
pub struct OnDiskJsonMonitor<F, M>
where
    F: FnMut(&mut M) -> bool,
    M: Monitor,
{
    base: M,
    path: PathBuf,
    /// A function that has the current runtime as argument and decides, whether a record should be logged
    log_record: F,
}

impl<F, M> OnDiskJsonMonitor<F, M>
where
    F: FnMut(&mut M) -> bool,
    M: Monitor,
{
    /// Create a new [`OnDiskJsonMonitor`]
    pub fn new<P>(filename: P, base: M, log_record: F) -> Self
    where
        P: Into<PathBuf>,
    {
        let path = filename.into();

        Self {
            base,
            path,
            log_record,
        }
    }
}

impl<F, M> Monitor for OnDiskJsonMonitor<F, M>
where
    F: FnMut(&mut M) -> bool,
    M: Monitor,
{
    fn client_stats_mut(&mut self) -> &mut Vec<ClientStats> {
        self.base.client_stats_mut()
    }

    fn client_stats(&self) -> &[ClientStats] {
        self.base.client_stats()
    }

    fn start_time(&self) -> Duration {
        self.base.start_time()
    }

    fn set_start_time(&mut self, time: Duration) {
        self.base.set_start_time(time);
    }

    fn display(&mut self, event_msg: &str, sender_id: ClientId) {
        if (self.log_record)(&mut self.base) {
            let file = OpenOptions::new()
                .append(true)
                .create(true)
                .open(&self.path)
                .expect("Failed to open logging file");

            let line = json!({
                "run_time": current_time() - self.base.start_time(),
                "clients": self.client_stats_count(),
                "corpus": self.base.corpus_size(),
                "objectives": self.base.objective_size(),
                "executions": self.base.total_execs(),
                "exec_sec": self.base.execs_per_sec(),
                "client_stats": self.client_stats(),
            });
            writeln!(&file, "{line}").expect("Unable to write Json to file");
        }
        self.base.display(event_msg, sender_id);
    }
}

#[derive(Debug, Clone)]
/// Wraps a base monitor and continuously appends
/// the current statistics to a CSV file.
pub struct OnDiskCSVMonitor<M>
where
    M: Monitor,
{
    base: M,
    fobj: *mut File,
    last_update: Duration,
    update_interval: Duration,
}

impl<M> OnDiskCSVMonitor<M>
where
    M: Monitor,
{
    /// Create new [`OnDiskCSVMonitor`]
    #[must_use]
    pub fn new(fileptr: *mut File, base: M) -> Self {
        Self::with_update_interval(fileptr, base, Duration::from_secs(60))
    }

    /// Create new [`OnDiskCSVMonitor`] with custom update interval
    #[must_use]
    pub fn with_update_interval(fileptr: *mut File, base: M, update_interval: Duration) -> Self {
        if fileptr == std::ptr::null_mut() {
            panic!("File pointer is null");
        }

        if true {
            // write csv header.
            // run time, corpus id, corpus size, objective size, executions, execs_per_sec, coverage
            let mut fileref = unsafe { fileptr.as_ref().unwrap() };
            writeln!(
                fileref,
                "run_time,corpus_id,corpus_size,fast_corpus_size,objective_size,executions,execs_per_sec,coverage"
            )
            .expect("Failed to write to the CSV file");

            fileref.sync_all().expect("Failed to sync the CSV file");
        }

        Self {
            base,
            fobj: fileptr,
            last_update: current_time() - update_interval,
            update_interval,
        }
    }
}

impl<M> Monitor for OnDiskCSVMonitor<M>
where
    M: Monitor,
{
    /// The client monitor, mutable
    fn client_stats_mut(&mut self) -> &mut Vec<ClientStats> {
        self.base.client_stats_mut()
    }

    /// The client monitor
    fn client_stats(&self) -> &[ClientStats] {
        self.base.client_stats()
    }

    /// Time this fuzzing run stated
    fn start_time(&self) -> Duration {
        self.base.start_time()
    }

    /// Set creation time
    fn set_start_time(&mut self, time: Duration) {
        self.base.set_start_time(time);
    }

    fn aggregate(&mut self, name: &str) {
        self.base.aggregate(name);
    }

    fn display(&mut self, event_msg: &str, sender_id: ClientId) {
        let cur_time = current_time();
        let run_time = cur_time - self.start_time();

        let fileptr = self.fobj;
        let mut fileref = unsafe { fileptr.as_ref().unwrap() };

        if cur_time - self.last_update >= self.update_interval {
            self.last_update = cur_time;

            let clients = self.client_stats_mut();

            for (i, client) in clients.iter_mut().enumerate() {
                let exec_sec = client.execs_per_sec(cur_time);

                // run time as H:M:S
                let secs = run_time.as_secs();
                write!(
                    fileref,
                    "\"{}:{}:{}\", ",
                    secs / 3600,
                    secs % 3600 / 60,
                    secs % 60
                )
                .expect("Failed to write to the csv file");

                // corpus id, corpus size, objective size, executions, execs_per_sec, coverage
                write!(
                    fileref,
                    "{}, {}, {}, {}, {}, {}, ",
                    i,
                    client.corpus_size,
                    client.fast_corpus_size,
                    client.objective_size,
                    client.executions,
                    exec_sec
                )
                .expect("Failed to write to the csv file");

                let mut pair_cnt = 0;
                for (_key, val) in &client.user_monitor {
                    write!(fileref, "\"{val}\", ").expect("Failed to write to the csv file");
                    pair_cnt += 1;
                }

                if pair_cnt == 0 {
                    // no coverage info found
                    write!(fileref, "\"???\", ").expect("Failed to write to the csv file");
                }

                write!(fileref, "\n").expect("Failed to write to the csv file");

                fileref.sync_all().expect("Failed to sync the csv file");
            }
        }

        self.base.display(event_msg, sender_id);
    }
}
