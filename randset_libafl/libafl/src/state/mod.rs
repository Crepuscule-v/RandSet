//! The fuzzer, and state are the core pieces of every good fuzzer

#[cfg(feature = "std")]
use alloc::vec::Vec;
use core::{
    borrow::BorrowMut,
    cell::{Ref, RefMut},
    fmt::Debug,
    marker::PhantomData,
    ops::{Deref, DerefMut},
    time::Duration,
};
use std::io::BufRead;
#[cfg(feature = "std")]
use std::{
    fs,
    path::{Path, PathBuf},
};

#[allow(unused_imports)]
use crate::bitmap::{getrand64, popcount8, BitmapTrait, SparseBitmap};

#[cfg(feature = "std")]
use libafl_bolts::core_affinity::{CoreId, Cores};
use libafl_bolts::{
    rands::{Rand, StdRand},
    serdeany::{NamedSerdeAnyMap, SerdeAnyMap},
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

mod stack;
pub use stack::StageStack;

use crate::bitmap::Bitmap;
#[cfg(feature = "introspection")]
use crate::monitors::ClientPerfMonitor;
#[cfg(feature = "scalability_introspection")]
use crate::monitors::ScalabilityMonitor;
use crate::{
    corpus::{Corpus, CorpusId, HasCurrentCorpusId, HasTestcase, InMemoryCorpus, Testcase},
    events::{Event, EventFirer, LogSeverity},
    feedbacks::StateInitializer,
    fuzzer::{Evaluator, ExecuteInputResult},
    generators::Generator,
    inputs::{Input, NopInput, UsesInput},
    stages::{HasCurrentStageId, HasNestedStageStatus, StageId},
    Error, HasMetadata, HasNamedMetadata,
};

/// The maximum size of a testcase
pub const DEFAULT_MAX_SIZE: usize = 1_048_576;

/// map size
pub static mut MAP_SIZE: usize = 1 << 16;

/// favored corpus
static mut FAVORED_CORPUS: Vec<CorpusId> = vec![];

/// frontier node bitmap changed
static mut MAP_CHANGED: bool = false;

/// successor size
pub const MAX_SUCCESSOR_COUNT: usize = 1024;

/// max node per seed
pub const MAX_NODE_PER_SEED: usize = 1000;

/// default execution time: 0.5s
pub const DEFAULT_EXEC_TIME_US: f64 = 500_000.0;

/// The [`State`] of the fuzzer.
/// Contains all important information about the current run.
/// Will be used to restart the fuzzing process at any time.
pub trait State:
    UsesInput
    + Serialize
    + DeserializeOwned
    + MaybeHasClientPerfMonitor
    + MaybeHasScalabilityMonitor
    + HasCurrentCorpusId
    + HasCurrentStageId
    + Stoppable
{
}

/// Structs which implement this trait are aware of the state. This is used for type enforcement.
pub trait UsesState: UsesInput<Input = <Self::State as UsesInput>::Input> {
    /// The state known by this type.
    type State: State;
}

// blanket impl which automatically defines UsesInput for anything that implements UsesState
impl<KS> UsesInput for KS
where
    KS: UsesState,
{
    type Input = <KS::State as UsesInput>::Input;
}

/// Trait for elements offering a corpus
pub trait HasCorpus {
    /// The associated type implementing [`Corpus`].
    type Corpus: Corpus;

    /// The testcase corpus
    fn corpus(&self) -> &Self::Corpus;
    /// The testcase corpus (mutable)
    fn corpus_mut(&mut self) -> &mut Self::Corpus;
}

// Reflexivity
impl<C> HasCorpus for C
where
    C: Corpus,
{
    type Corpus = Self;

    fn corpus(&self) -> &Self::Corpus {
        self
    }

    fn corpus_mut(&mut self) -> &mut Self::Corpus {
        self
    }
}

/// Interact with the maximum size
pub trait HasMaxSize {
    /// The maximum size hint for items and mutations returned
    fn max_size(&self) -> usize;
    /// Sets the maximum size hint for the items and mutations
    fn set_max_size(&mut self, max_size: usize);
}

/// Trait for elements offering a corpus of solutions
pub trait HasSolutions {
    /// The associated type implementing [`Corpus`] for solutions
    type Solutions: Corpus;

    /// The solutions corpus
    fn solutions(&self) -> &Self::Solutions;
    /// The solutions corpus (mutable)
    fn solutions_mut(&mut self) -> &mut Self::Solutions;
}

/// Trait for elements offering a rand
pub trait HasRand {
    /// The associated type implementing [`Rand`]
    type Rand: Rand;
    /// The rand instance
    fn rand(&self) -> &Self::Rand;
    /// The rand instance (mutable)
    fn rand_mut(&mut self) -> &mut Self::Rand;
}

#[cfg(feature = "introspection")]
/// Trait for offering a [`ClientPerfMonitor`]
pub trait HasClientPerfMonitor {
    /// [`ClientPerfMonitor`] itself
    fn introspection_monitor(&self) -> &ClientPerfMonitor;

    /// Mutatable ref to [`ClientPerfMonitor`]
    fn introspection_monitor_mut(&mut self) -> &mut ClientPerfMonitor;
}

/// Intermediate trait for `HasClientPerfMonitor`
#[cfg(feature = "introspection")]
pub trait MaybeHasClientPerfMonitor: HasClientPerfMonitor {}

/// Intermediate trait for `HasClientPerfmonitor`
#[cfg(not(feature = "introspection"))]
pub trait MaybeHasClientPerfMonitor {}

#[cfg(not(feature = "introspection"))]
impl<T> MaybeHasClientPerfMonitor for T {}

#[cfg(feature = "introspection")]
impl<T> MaybeHasClientPerfMonitor for T where T: HasClientPerfMonitor {}

/// Intermediate trait for `HasScalabilityMonitor`
#[cfg(feature = "scalability_introspection")]
pub trait MaybeHasScalabilityMonitor: HasScalabilityMonitor {}
/// Intermediate trait for `HasScalabilityMonitor`
#[cfg(not(feature = "scalability_introspection"))]
pub trait MaybeHasScalabilityMonitor {}

#[cfg(not(feature = "scalability_introspection"))]
impl<T> MaybeHasScalabilityMonitor for T {}

#[cfg(feature = "scalability_introspection")]
impl<T> MaybeHasScalabilityMonitor for T where T: HasScalabilityMonitor {}

/// Trait for offering a [`ScalabilityMonitor`]
#[cfg(feature = "scalability_introspection")]
pub trait HasScalabilityMonitor {
    /// Ref to [`ScalabilityMonitor`]
    fn scalability_monitor(&self) -> &ScalabilityMonitor;

    /// Mutable ref to [`ScalabilityMonitor`]
    fn scalability_monitor_mut(&mut self) -> &mut ScalabilityMonitor;
}

/// Trait for the execution counter
pub trait HasExecutions {
    /// The executions counter
    fn executions(&self) -> &u64;

    /// The executions counter (mutable)
    fn executions_mut(&mut self) -> &mut u64;
}

/// Trait for some stats of AFL
pub trait HasImported {
    ///the imported testcases counter
    fn imported(&self) -> &usize;

    ///the imported testcases counter (mutable)
    fn imported_mut(&mut self) -> &mut usize;
}

/// Trait for the starting time
pub trait HasStartTime {
    /// The starting time
    fn start_time(&self) -> &Duration;

    /// The starting time (mutable)
    fn start_time_mut(&mut self) -> &mut Duration;
}

/// Trait for the last report time, the last time this node reported progress
pub trait HasLastFoundTime {
    /// The last time we found something by ourselves
    fn last_found_time(&self) -> &Duration;

    /// The last time we found something by ourselves (mutable)
    fn last_found_time_mut(&mut self) -> &mut Duration;
}

/// Trait for the last report time, the last time this node reported progress
pub trait HasLastReportTime {
    /// The last time we reported progress,if available/used.
    /// This information is used by fuzzer `maybe_report_progress`.
    fn last_report_time(&self) -> &Option<Duration>;

    /// The last time we reported progress,if available/used (mutable).
    /// This information is used by fuzzer `maybe_report_progress`.
    fn last_report_time_mut(&mut self) -> &mut Option<Duration>;
}

/// Trait for set cover scheduling
pub trait HasSetCover {
    /// Load the cfg file. Environment variable
    /// AFL_CFG_PATH must be set.
    fn load_cfg(&mut self);

    /// Change scheduling method to setcover.
    fn use_setcover_schedule(&mut self);

    /// Check if the edge is a frontier node.
    fn is_frontier_node_outer(&self, edge_id: usize) -> bool;

    /// Check if the edge is a frontier node.
    fn is_frontier_node_inner(&self, trace_bits: &Vec<u8>, edge_id: usize) -> bool;

    /// Update global frontier nodes.
    fn update_global_frontier_nodes(&mut self, id: CorpusId);

    /// Perform seed reduction.
    fn setcover_reduction(&mut self);

    /// Update bitmap score.
    fn update_bitmap_score(&mut self, trace_bits: Vec<u8>, id: CorpusId);

    /// Go over top rated entries and sequentially grab
    /// winners for previously unseen bytes and marks
    /// them as favored.
    fn cull_queue(&mut self);

    /// Write trace bits info to disk.
    fn write_trace_bits_info(&self) {
        panic!("not implemented yet");
    }
}

/// Struct that holds the options for input loading
#[cfg(feature = "std")]
pub struct LoadConfig<'a, I, S, Z> {
    /// Load Input even if it was deemed "uninteresting" by the fuzzer
    forced: bool,
    /// Function to load input from a Path
    loader: &'a mut dyn FnMut(&mut Z, &mut S, &Path) -> Result<I, Error>,
    /// Error if Input leads to a Solution.
    exit_on_solution: bool,
}

#[cfg(feature = "std")]
impl<I, S, Z> Debug for LoadConfig<'_, I, S, Z> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "LoadConfig {{}}")
    }
}

/// The state a fuzz run.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "
        C: serde::Serialize + for<'a> serde::Deserialize<'a>,
        SC: serde::Serialize + for<'a> serde::Deserialize<'a>,
        R: serde::Serialize + for<'a> serde::Deserialize<'a>
    ")]
pub struct StdState<I, C, R, SC> {
    /// RNG instance
    rand: R,
    /// How many times the executor ran the harness/target
    executions: u64,
    /// At what time the fuzzing started
    start_time: Duration,
    /// the number of new paths that imported from other fuzzers
    imported: usize,
    /// The corpus
    corpus: C,
    // Solutions corpus
    solutions: SC,
    /// Metadata stored for this state by one of the components
    metadata: SerdeAnyMap,
    /// Metadata stored with names
    named_metadata: NamedSerdeAnyMap,
    /// `MaxSize` testcase size for mutators that appreciate it
    max_size: usize,
    /// Performance statistics for this fuzzer
    #[cfg(feature = "introspection")]
    introspection_monitor: ClientPerfMonitor,
    #[cfg(feature = "scalability_introspection")]
    scalability_monitor: ScalabilityMonitor,
    #[cfg(feature = "std")]
    /// Remaining initial inputs to load, if any
    remaining_initial_files: Option<Vec<PathBuf>>,
    #[cfg(feature = "std")]
    /// symlinks we have already traversed when loading `remaining_initial_files`
    dont_reenter: Option<Vec<PathBuf>>,
    #[cfg(feature = "std")]
    /// If inputs have been processed for multicore loading
    /// relevant only for `load_initial_inputs_multicore`
    multicore_inputs_processed: Option<bool>,
    /// The last time we reported progress (if available/used).
    /// This information is used by fuzzer `maybe_report_progress`.
    last_report_time: Option<Duration>,
    /// The last time something was added to the corpus
    last_found_time: Duration,
    /// The current index of the corpus; used to record for resumable fuzzing.
    corpus_id: Option<CorpusId>,
    /// Request the fuzzer to stop at the start of the next stage
    /// or at the beginning of the next fuzzing iteration
    stop_requested: bool,
    stage_stack: StageStack,
    phantom: PhantomData<I>,
    /// needed by our setcover method.
    global_frontier_bitmap: Bitmap,
    global_frontier_bitmap_searched: Bitmap,
    initial_frontier_bitmap: Bitmap,
    local_covered: Bitmap,
    use_setcover_scheduling: bool,
    removed_frontier_found: bool,
    new_frontier_found: bool,
    global_frontier_updated: bool,
    /// record changes of bitmap score
    score_changed: bool,
    /// forkserver
    successor_map: Vec<Vec<u32>>,
    successor_count: Vec<u32>,
    virgin_bits: Vec<u8>,
    /// Top entries for bitmap bytes
    top_rated: Vec<Option<CorpusId>>,
    // FIXME: These are probably unused.
    // recent_frontier_nodes: Vec<u32>,
    // frontier_discovery_time: Vec<u32>,
}

impl<I, C, R, SC> UsesInput for StdState<I, C, R, SC>
where
    I: Input,
{
    type Input = I;
}

impl<I, C, R, SC> State for StdState<I, C, R, SC>
where
    C: Corpus<Input = Self::Input> + Serialize + DeserializeOwned,
    R: Rand,
    SC: Corpus<Input = Self::Input> + Serialize + DeserializeOwned,
    Self: UsesInput,
{
}

impl<I, C, R, SC> HasRand for StdState<I, C, R, SC>
where
    R: Rand,
{
    type Rand = R;

    /// The rand instance
    #[inline]
    fn rand(&self) -> &Self::Rand {
        &self.rand
    }

    /// The rand instance (mutable)
    #[inline]
    fn rand_mut(&mut self) -> &mut Self::Rand {
        &mut self.rand
    }
}

impl<I, C, R, SC> HasCorpus for StdState<I, C, R, SC>
where
    C: Corpus,
{
    type Corpus = C;

    /// Returns the corpus
    #[inline]
    fn corpus(&self) -> &Self::Corpus {
        &self.corpus
    }

    /// Returns the mutable corpus
    #[inline]
    fn corpus_mut(&mut self) -> &mut Self::Corpus {
        &mut self.corpus
    }
}

impl<I, C, R, SC> HasTestcase for StdState<I, C, R, SC>
where
    C: Corpus,
{
    /// To get the testcase
    fn testcase(&self, id: CorpusId) -> Result<Ref<'_, Testcase<C::Input>>, Error> {
        Ok(self.corpus().get(id)?.borrow())
    }

    /// To get mutable testcase
    fn testcase_mut(&self, id: CorpusId) -> Result<RefMut<'_, Testcase<C::Input>>, Error> {
        Ok(self.corpus().get(id)?.borrow_mut())
    }
}

impl<I, C, R, SC> HasSolutions for StdState<I, C, R, SC>
where
    I: Input,
    SC: Corpus<Input = <Self as UsesInput>::Input>,
{
    type Solutions = SC;

    /// Returns the solutions corpus
    #[inline]
    fn solutions(&self) -> &SC {
        &self.solutions
    }

    /// Returns the solutions corpus (mutable)
    #[inline]
    fn solutions_mut(&mut self) -> &mut SC {
        &mut self.solutions
    }
}

impl<I, C, R, SC> HasMetadata for StdState<I, C, R, SC> {
    /// Get all the metadata into an [`hashbrown::HashMap`]
    #[inline]
    fn metadata_map(&self) -> &SerdeAnyMap {
        &self.metadata
    }

    /// Get all the metadata into an [`hashbrown::HashMap`] (mutable)
    #[inline]
    fn metadata_map_mut(&mut self) -> &mut SerdeAnyMap {
        &mut self.metadata
    }
}

impl<I, C, R, SC> HasNamedMetadata for StdState<I, C, R, SC> {
    /// Get all the metadata into an [`hashbrown::HashMap`]
    #[inline]
    fn named_metadata_map(&self) -> &NamedSerdeAnyMap {
        &self.named_metadata
    }

    /// Get all the metadata into an [`hashbrown::HashMap`] (mutable)
    #[inline]
    fn named_metadata_map_mut(&mut self) -> &mut NamedSerdeAnyMap {
        &mut self.named_metadata
    }
}

impl<I, C, R, SC> HasExecutions for StdState<I, C, R, SC> {
    /// The executions counter
    #[inline]
    fn executions(&self) -> &u64 {
        &self.executions
    }

    /// The executions counter (mutable)
    #[inline]
    fn executions_mut(&mut self) -> &mut u64 {
        &mut self.executions
    }
}

impl<I, C, R, SC> HasImported for StdState<I, C, R, SC> {
    /// Return the number of new paths that imported from other fuzzers
    #[inline]
    fn imported(&self) -> &usize {
        &self.imported
    }

    /// Return the number of new paths that imported from other fuzzers
    #[inline]
    fn imported_mut(&mut self) -> &mut usize {
        &mut self.imported
    }
}

impl<I, C, R, SC> HasLastFoundTime for StdState<I, C, R, SC> {
    /// Return the number of new paths that imported from other fuzzers
    #[inline]
    fn last_found_time(&self) -> &Duration {
        &self.last_found_time
    }

    /// Return the number of new paths that imported from other fuzzers
    #[inline]
    fn last_found_time_mut(&mut self) -> &mut Duration {
        &mut self.last_found_time
    }
}

impl<I, C, R, SC> HasLastReportTime for StdState<I, C, R, SC> {
    /// The last time we reported progress,if available/used.
    /// This information is used by fuzzer `maybe_report_progress`.
    fn last_report_time(&self) -> &Option<Duration> {
        &self.last_report_time
    }

    /// The last time we reported progress,if available/used (mutable).
    /// This information is used by fuzzer `maybe_report_progress`.
    fn last_report_time_mut(&mut self) -> &mut Option<Duration> {
        &mut self.last_report_time
    }
}

impl<I, C, R, SC> HasMaxSize for StdState<I, C, R, SC> {
    fn max_size(&self) -> usize {
        self.max_size
    }

    fn set_max_size(&mut self, max_size: usize) {
        self.max_size = max_size;
    }
}

impl<I, C, R, SC> HasStartTime for StdState<I, C, R, SC> {
    /// The starting time
    #[inline]
    fn start_time(&self) -> &Duration {
        &self.start_time
    }

    /// The starting time (mutable)
    #[inline]
    fn start_time_mut(&mut self) -> &mut Duration {
        &mut self.start_time
    }
}

impl<I, C, R, SC> HasCurrentCorpusId for StdState<I, C, R, SC> {
    fn set_corpus_id(&mut self, id: CorpusId) -> Result<(), Error> {
        self.corpus_id = Some(id);
        Ok(())
    }

    fn clear_corpus_id(&mut self) -> Result<(), Error> {
        self.corpus_id = None;
        Ok(())
    }

    fn current_corpus_id(&self) -> Result<Option<CorpusId>, Error> {
        Ok(self.corpus_id)
    }
}

/// Has information about the current [`Testcase`] we are fuzzing
pub trait HasCurrentTestcase: HasCorpus {
    /// Gets the current [`Testcase`] we are fuzzing
    ///
    /// Will return [`Error::key_not_found`] if no `corpus_id` is currently set.
    fn current_testcase(&self)
        -> Result<Ref<'_, Testcase<<Self::Corpus as Corpus>::Input>>, Error>;
    //fn current_testcase(&self) -> Result<&Testcase<I>, Error>;

    /// Gets the current [`Testcase`] we are fuzzing (mut)
    ///
    /// Will return [`Error::key_not_found`] if no `corpus_id` is currently set.
    fn current_testcase_mut(
        &self,
    ) -> Result<RefMut<'_, Testcase<<Self::Corpus as Corpus>::Input>>, Error>;
    //fn current_testcase_mut(&self) -> Result<&mut Testcase<I>, Error>;

    /// Gets a cloned representation of the current [`Testcase`].
    ///
    /// Will return [`Error::key_not_found`] if no `corpus_id` is currently set.
    ///
    /// # Note
    /// This allocates memory and copies the contents!
    /// For performance reasons, if you just need to access the testcase, use [`Self::current_testcase`] instead.
    fn current_input_cloned(&self) -> Result<<Self::Corpus as Corpus>::Input, Error>;
}

impl<T> HasCurrentTestcase for T
where
    T: HasCorpus + HasCurrentCorpusId,
    <Self::Corpus as Corpus>::Input: Clone,
{
    fn current_testcase(
        &self,
    ) -> Result<Ref<'_, Testcase<<Self::Corpus as Corpus>::Input>>, Error> {
        let Some(corpus_id) = self.current_corpus_id()? else {
            return Err(Error::key_not_found(
                "We are not currently processing a testcase",
            ));
        };

        Ok(self.corpus().get(corpus_id)?.borrow())
    }

    fn current_testcase_mut(
        &self,
    ) -> Result<RefMut<'_, Testcase<<Self::Corpus as Corpus>::Input>>, Error> {
        let Some(corpus_id) = self.current_corpus_id()? else {
            return Err(Error::illegal_state(
                "We are not currently processing a testcase",
            ));
        };

        Ok(self.corpus().get(corpus_id)?.borrow_mut())
    }

    fn current_input_cloned(&self) -> Result<<Self::Corpus as Corpus>::Input, Error> {
        let mut testcase = self.current_testcase_mut()?;
        Ok(testcase.borrow_mut().load_input(self.corpus())?.clone())
    }
}

/// A trait for types that want to expose a stop API
pub trait Stoppable {
    /// Check if stop is requested
    fn stop_requested(&self) -> bool;

    /// Request to stop
    fn request_stop(&mut self);

    /// Discard the stop request
    fn discard_stop_request(&mut self);
}

impl<I, C, R, SC> Stoppable for StdState<I, C, R, SC> {
    fn request_stop(&mut self) {
        self.stop_requested = true;
    }

    fn discard_stop_request(&mut self) {
        self.stop_requested = false;
    }

    fn stop_requested(&self) -> bool {
        self.stop_requested
    }
}

impl<I, C, R, SC> HasCurrentStageId for StdState<I, C, R, SC> {
    fn set_current_stage_id(&mut self, idx: StageId) -> Result<(), Error> {
        self.stage_stack.set_current_stage_id(idx)
    }

    fn clear_stage_id(&mut self) -> Result<(), Error> {
        self.stage_stack.clear_stage_id()
    }

    fn current_stage_id(&self) -> Result<Option<StageId>, Error> {
        self.stage_stack.current_stage_id()
    }

    fn on_restart(&mut self) -> Result<(), Error> {
        self.stage_stack.on_restart()
    }
}

impl<I, C, R, SC> HasNestedStageStatus for StdState<I, C, R, SC> {
    fn enter_inner_stage(&mut self) -> Result<(), Error> {
        self.stage_stack.enter_inner_stage()
    }

    fn exit_inner_stage(&mut self) -> Result<(), Error> {
        self.stage_stack.exit_inner_stage()
    }
}

#[cfg(feature = "std")]
impl<C, I, R, SC> StdState<I, C, R, SC>
where
    I: Input,
    C: Corpus<Input = <Self as UsesInput>::Input>,
    R: Rand,
    SC: Corpus<Input = <Self as UsesInput>::Input>,
{
    /// Decide if the state must load the inputs
    pub fn must_load_initial_inputs(&self) -> bool {
        self.corpus().count() == 0
            || (self.remaining_initial_files.is_some()
                && !self.remaining_initial_files.as_ref().unwrap().is_empty())
    }

    /// List initial inputs from a directory.
    fn next_file(&mut self) -> Result<PathBuf, Error> {
        loop {
            if let Some(path) = self.remaining_initial_files.as_mut().and_then(Vec::pop) {
                let filename = path.file_name().unwrap().to_string_lossy();
                println!("Loading initial input: {filename}");
                if filename.starts_with('.')
                // || filename
                //     .rsplit_once('-')
                //     .is_some_and(|(_, s)| u64::from_str(s).is_ok())
                {
                    continue;
                }

                let attributes = fs::metadata(&path);

                if attributes.is_err() {
                    continue;
                }

                let attr = attributes?;

                if attr.is_file() && attr.len() > 0 {
                    return Ok(path);
                } else if attr.is_dir() {
                    let files = self.remaining_initial_files.as_mut().unwrap();
                    path.read_dir()?
                        .try_for_each(|entry| entry.map(|e| files.push(e.path())))?;
                } else if attr.is_symlink() {
                    let path = fs::canonicalize(path)?;
                    let dont_reenter = self.dont_reenter.get_or_insert_with(Default::default);
                    if dont_reenter.iter().any(|p| path.starts_with(p)) {
                        continue;
                    }
                    if path.is_dir() {
                        dont_reenter.push(path.clone());
                    }
                    let files = self.remaining_initial_files.as_mut().unwrap();
                    files.push(path);
                }
            } else {
                return Err(Error::iterator_end("No remaining files to load."));
            }
        }
    }

    /// Resets the state of initial files.
    fn reset_initial_files_state(&mut self) {
        self.remaining_initial_files = None;
        self.dont_reenter = None;
    }

    /// Sets canonical paths for provided inputs
    fn canonicalize_input_dirs(&mut self, in_dirs: &[PathBuf]) -> Result<(), Error> {
        if let Some(remaining) = self.remaining_initial_files.as_ref() {
            // everything was loaded
            if remaining.is_empty() {
                return Ok(());
            }
        } else {
            let files = in_dirs.iter().try_fold(Vec::new(), |mut res, file| {
                file.canonicalize().map(|canonicalized| {
                    res.push(canonicalized);
                    res
                })
            })?;
            self.dont_reenter = Some(files.clone());
            self.remaining_initial_files = Some(files);
        }
        Ok(())
    }

    /// Loads initial inputs from the passed-in `in_dirs`.
    /// If `forced` is true, will add all testcases, no matter what.
    /// This method takes a list of files.
    fn load_initial_inputs_custom_by_filenames<E, EM, Z>(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        manager: &mut EM,
        file_list: &[PathBuf],
        load_config: LoadConfig<I, Self, Z>,
    ) -> Result<(), Error>
    where
        E: UsesState<State = Self>,
        EM: EventFirer<State = Self>,
        Z: Evaluator<E, EM, I, Self>,
    {
        if let Some(remaining) = self.remaining_initial_files.as_ref() {
            // everything was loaded
            if remaining.is_empty() {
                return Ok(());
            }
        } else {
            self.remaining_initial_files = Some(file_list.to_vec());
        }

        self.continue_loading_initial_inputs_custom(fuzzer, executor, manager, load_config)
    }

    fn load_file<E, EM, Z>(
        &mut self,
        path: &PathBuf,
        manager: &mut EM,
        fuzzer: &mut Z,
        executor: &mut E,
        config: &mut LoadConfig<I, Self, Z>,
    ) -> Result<ExecuteInputResult, Error>
    where
        E: UsesState<State = Self>,
        EM: EventFirer<State = Self>,
        Z: Evaluator<E, EM, I, Self>,
    {
        log::info!("Loading file {:?} ...", &path);
        let input = (config.loader)(fuzzer, self, path)?;
        if config.forced {
            let _: CorpusId = fuzzer.add_input(self, executor, manager, input)?;
            Ok(ExecuteInputResult::Corpus)
        } else {
            let (res, _) = fuzzer.evaluate_input(self, executor, manager, input.clone())?;
            if res == ExecuteInputResult::None {
                fuzzer.add_disabled_input(self, input)?;
                log::warn!("input {:?} was not interesting, adding as disabled.", &path);
            }
            Ok(res)
        }
    }
    /// Loads initial inputs from the passed-in `in_dirs`.
    /// This method takes a list of files and a `LoadConfig`
    /// which specifies the special handling of initial inputs
    fn continue_loading_initial_inputs_custom<E, EM, Z>(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        manager: &mut EM,
        mut config: LoadConfig<I, Self, Z>,
    ) -> Result<(), Error>
    where
        E: UsesState<State = Self>,
        EM: EventFirer<State = Self>,
        Z: Evaluator<E, EM, I, Self>,
    {
        loop {
            match self.next_file() {
                Ok(path) => {
                    let res = self.load_file(&path, manager, fuzzer, executor, &mut config)?;
                    if config.exit_on_solution && matches!(res, ExecuteInputResult::Solution) {
                        return Err(Error::invalid_corpus(format!(
                            "Input {} resulted in a solution.",
                            path.display()
                        )));
                    }
                }
                Err(Error::IteratorEnd(_, _)) => break,
                Err(e) => return Err(e),
            }
        }

        manager.fire(
            self,
            Event::Log {
                severity_level: LogSeverity::Debug,
                message: format!("Loaded {} initial testcases.", self.corpus().count()), // get corpus count
                phantom: PhantomData::<I>,
            },
        )?;
        Ok(())
    }

    /// Recursively walk supplied corpus directories
    pub fn walk_initial_inputs<F>(
        &mut self,
        in_dirs: &[PathBuf],
        mut closure: F,
    ) -> Result<(), Error>
    where
        F: FnMut(&PathBuf) -> Result<(), Error>,
    {
        self.canonicalize_input_dirs(in_dirs)?;
        loop {
            match self.next_file() {
                Ok(path) => {
                    closure(&path)?;
                }
                Err(Error::IteratorEnd(_, _)) => break,
                Err(e) => return Err(e),
            }
        }
        self.reset_initial_files_state();
        Ok(())
    }
    /// Loads all intial inputs, even if they are not considered `interesting`.
    /// This is rarely the right method, use `load_initial_inputs`,
    /// and potentially fix your `Feedback`, instead.
    /// This method takes a list of files, instead of folders.
    pub fn load_initial_inputs_by_filenames<E, EM, Z>(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        manager: &mut EM,
        file_list: &[PathBuf],
    ) -> Result<(), Error>
    where
        E: UsesState<State = Self>,
        EM: EventFirer<State = Self>,
        Z: Evaluator<E, EM, I, Self>,
    {
        self.load_initial_inputs_custom_by_filenames(
            fuzzer,
            executor,
            manager,
            file_list,
            LoadConfig {
                loader: &mut |_, _, path| I::from_file(path),
                forced: false,
                exit_on_solution: false,
            },
        )
    }

    /// Loads all intial inputs, even if they are not considered `interesting`.
    /// This is rarely the right method, use `load_initial_inputs`,
    /// and potentially fix your `Feedback`, instead.
    pub fn load_initial_inputs_forced<E, EM, Z>(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        manager: &mut EM,
        in_dirs: &[PathBuf],
    ) -> Result<(), Error>
    where
        E: UsesState<State = Self>,
        EM: EventFirer<State = Self>,
        Z: Evaluator<E, EM, I, Self>,
    {
        self.canonicalize_input_dirs(in_dirs)?;
        self.continue_loading_initial_inputs_custom(
            fuzzer,
            executor,
            manager,
            LoadConfig {
                loader: &mut |_, _, path| I::from_file(path),
                forced: true,
                exit_on_solution: false,
            },
        )
    }
    /// Loads initial inputs from the passed-in `in_dirs`.
    /// If `forced` is true, will add all testcases, no matter what.
    /// This method takes a list of files, instead of folders.
    pub fn load_initial_inputs_by_filenames_forced<E, EM, Z>(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        manager: &mut EM,
        file_list: &[PathBuf],
    ) -> Result<(), Error>
    where
        E: UsesState<State = Self>,
        EM: EventFirer<State = Self>,
        Z: Evaluator<E, EM, I, Self>,
    {
        self.load_initial_inputs_custom_by_filenames(
            fuzzer,
            executor,
            manager,
            file_list,
            LoadConfig {
                loader: &mut |_, _, path| I::from_file(path),
                forced: true,
                exit_on_solution: false,
            },
        )
    }

    /// Loads initial inputs from the passed-in `in_dirs`.
    pub fn load_initial_inputs<E, EM, Z>(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        manager: &mut EM,
        in_dirs: &[PathBuf],
    ) -> Result<(), Error>
    where
        E: UsesState<State = Self>,
        EM: EventFirer<State = Self>,
        Z: Evaluator<E, EM, I, Self>,
    {
        self.canonicalize_input_dirs(in_dirs)?;
        self.continue_loading_initial_inputs_custom(
            fuzzer,
            executor,
            manager,
            LoadConfig {
                loader: &mut |_, _, path| I::from_file(path),
                forced: false,
                exit_on_solution: false,
            },
        )
    }

    /// Loads initial inputs from the passed-in `in_dirs`.
    /// Will return a `CorpusError` if a solution is found
    pub fn load_initial_inputs_disallow_solution<E, EM, Z>(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        manager: &mut EM,
        in_dirs: &[PathBuf],
    ) -> Result<(), Error>
    where
        E: UsesState<State = Self>,
        EM: EventFirer<State = Self>,
        Z: Evaluator<E, EM, I, Self>,
    {
        self.canonicalize_input_dirs(in_dirs)?;
        self.continue_loading_initial_inputs_custom(
            fuzzer,
            executor,
            manager,
            LoadConfig {
                loader: &mut |_, _, path| I::from_file(path),
                forced: false,
                exit_on_solution: true,
            },
        )
    }

    fn calculate_corpus_size(&mut self) -> Result<usize, Error> {
        let mut count: usize = 0;
        loop {
            match self.next_file() {
                Ok(_) => {
                    count = count.saturating_add(1);
                }
                Err(Error::IteratorEnd(_, _)) => break,
                Err(e) => return Err(e),
            }
        }
        Ok(count)
    }
    /// Loads initial inputs by dividing the from the passed-in `in_dirs`
    /// in a multicore fashion. Divides the corpus in chunks spread across cores.
    pub fn load_initial_inputs_multicore<E, EM, Z>(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        manager: &mut EM,
        in_dirs: &[PathBuf],
        core_id: &CoreId,
        cores: &Cores,
    ) -> Result<(), Error>
    where
        E: UsesState<State = Self>,
        EM: EventFirer<State = Self>,
        Z: Evaluator<E, EM, I, Self>,
    {
        if self.multicore_inputs_processed.unwrap_or(false) {
            self.continue_loading_initial_inputs_custom(
                fuzzer,
                executor,
                manager,
                LoadConfig {
                    loader: &mut |_, _, path| I::from_file(path),
                    forced: false,
                    exit_on_solution: false,
                },
            )?;
        } else {
            self.canonicalize_input_dirs(in_dirs)?;
            let corpus_size = self.calculate_corpus_size()?;
            log::info!(
                "{} total_corpus_size, {} cores",
                corpus_size,
                cores.ids.len()
            );
            self.reset_initial_files_state();
            self.canonicalize_input_dirs(in_dirs)?;
            if cores.ids.len() > corpus_size {
                log::info!(
                    "low intial corpus count ({}), no parallelism required.",
                    corpus_size
                );
            } else {
                let core_index = cores
                    .ids
                    .iter()
                    .enumerate()
                    .find(|(_, c)| *c == core_id)
                    .unwrap_or_else(|| panic!("core id {} not in cores list", core_id.0))
                    .0;
                let chunk_size = corpus_size.saturating_div(cores.ids.len());
                let mut skip = core_index.saturating_mul(chunk_size);
                let mut inputs_todo = chunk_size;
                let mut collected_inputs = Vec::new();
                log::info!(
                    "core = {}, core_index = {}, chunk_size = {}, skip = {}",
                    core_id.0,
                    core_index,
                    chunk_size,
                    skip
                );
                loop {
                    match self.next_file() {
                        Ok(path) => {
                            if skip != 0 {
                                skip = skip.saturating_sub(1);
                                continue;
                            }
                            if inputs_todo == 0 {
                                break;
                            }
                            collected_inputs.push(path);
                            inputs_todo = inputs_todo.saturating_sub(1);
                        }
                        Err(Error::IteratorEnd(_, _)) => break,
                        Err(e) => {
                            return Err(e);
                        }
                    }
                }
                self.remaining_initial_files = Some(collected_inputs);
            }
            self.multicore_inputs_processed = Some(true);
            return self
                .load_initial_inputs_multicore(fuzzer, executor, manager, in_dirs, core_id, cores);
        }
        Ok(())
    }
}

impl<C, I, R, SC> StdState<I, C, R, SC>
where
    I: Input,
    C: Corpus<Input = <Self as UsesInput>::Input>,
    R: Rand,
    SC: Corpus<Input = <Self as UsesInput>::Input>,
{
    fn generate_initial_internal<G, E, EM, Z>(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        generator: &mut G,
        manager: &mut EM,
        num: usize,
        forced: bool,
    ) -> Result<(), Error>
    where
        E: UsesState<State = Self>,
        EM: EventFirer<State = Self>,
        G: Generator<<Self as UsesInput>::Input, Self>,
        Z: Evaluator<E, EM, I, Self>,
    {
        let mut added = 0;
        for _ in 0..num {
            let input = generator.generate(self)?;
            if forced {
                let _: CorpusId = fuzzer.add_input(self, executor, manager, input)?;
                added += 1;
            } else {
                let (res, _) = fuzzer.evaluate_input(self, executor, manager, input)?;
                if res != ExecuteInputResult::None {
                    added += 1;
                }
            }
        }
        manager.fire(
            self,
            Event::Log {
                severity_level: LogSeverity::Debug,
                message: format!("Loaded {added} over {num} initial testcases"),
                phantom: PhantomData,
            },
        )?;
        Ok(())
    }

    /// Generate `num` initial inputs, using the passed-in generator and force the addition to corpus.
    pub fn generate_initial_inputs_forced<G, E, EM, Z>(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        generator: &mut G,
        manager: &mut EM,
        num: usize,
    ) -> Result<(), Error>
    where
        E: UsesState<State = Self>,
        EM: EventFirer<State = Self>,
        G: Generator<<Self as UsesInput>::Input, Self>,
        Z: Evaluator<E, EM, I, Self>,
    {
        self.generate_initial_internal(fuzzer, executor, generator, manager, num, true)
    }

    /// Generate `num` initial inputs, using the passed-in generator.
    pub fn generate_initial_inputs<G, E, EM, Z>(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        generator: &mut G,
        manager: &mut EM,
        num: usize,
    ) -> Result<(), Error>
    where
        E: UsesState<State = Self>,
        EM: EventFirer<State = Self>,
        G: Generator<<Self as UsesInput>::Input, Self>,
        Z: Evaluator<E, EM, I, Self>,
    {
        self.generate_initial_internal(fuzzer, executor, generator, manager, num, false)
    }

    /// Returns the map size.
    pub fn get_map_size(self) -> usize {
        return self.successor_map.len();
    }

    /// Creates a new `State`, taking ownership of all of the individual components during fuzzing.
    pub fn new<F, O>(
        rand: R,
        corpus: C,
        solutions: SC,
        feedback: &mut F,
        objective: &mut O,
    ) -> Result<Self, Error>
    where
        F: StateInitializer<Self>,
        O: StateInitializer<Self>,
        C: Serialize + DeserializeOwned,
        SC: Serialize + DeserializeOwned,
    {
        let mut state = Self {
            rand,
            executions: 0,
            imported: 0,
            start_time: libafl_bolts::current_time(),
            metadata: SerdeAnyMap::default(),
            named_metadata: NamedSerdeAnyMap::default(),
            corpus,
            solutions,
            max_size: DEFAULT_MAX_SIZE,
            stop_requested: false,
            #[cfg(feature = "introspection")]
            introspection_monitor: ClientPerfMonitor::new(),
            #[cfg(feature = "scalability_introspection")]
            scalability_monitor: ScalabilityMonitor::new(),
            #[cfg(feature = "std")]
            remaining_initial_files: None,
            #[cfg(feature = "std")]
            dont_reenter: None,
            last_report_time: None,
            last_found_time: libafl_bolts::current_time(),
            corpus_id: None,
            stage_stack: StageStack::default(),
            phantom: PhantomData,
            #[cfg(feature = "std")]
            multicore_inputs_processed: None,
            global_frontier_bitmap: Bitmap::new(unsafe { MAP_SIZE }),
            global_frontier_bitmap_searched: Bitmap::new(unsafe { MAP_SIZE} ),
            initial_frontier_bitmap: Bitmap::new(unsafe { MAP_SIZE }),
            local_covered: Bitmap::new(unsafe { MAP_SIZE }),
            new_frontier_found: false,
            removed_frontier_found: false,
            global_frontier_updated: false,
            use_setcover_scheduling: false,
            score_changed: false,
            successor_map: vec![],   // init in load_cfg()
            successor_count: vec![], // init in load_cfg()
            virgin_bits: vec![],     // init in load_cfg()
            top_rated: vec![None; unsafe { MAP_SIZE }], // maybe resized in load_cfg()
        };
        feedback.init_state(&mut state)?;
        objective.init_state(&mut state)?;
        Ok(state)
    }
}

struct ControlFlowGraphEdge {
    src: usize,
    dst: usize,
}

impl Default for ControlFlowGraphEdge {
    fn default() -> Self {
        ControlFlowGraphEdge { src: 0, dst: 0 }
    }
}

impl Clone for ControlFlowGraphEdge {
    fn clone(&self) -> Self {
        ControlFlowGraphEdge {
            src: self.src,
            dst: self.dst,
        }
    }
}

impl<C, I, R, SC> HasSetCover for StdState<I, C, R, SC>
where
    I: Input,
    C: Corpus<Input = <Self as UsesInput>::Input>,
    R: Rand,
    SC: Corpus<Input = <Self as UsesInput>::Input>,
{
    fn load_cfg(&mut self) {
        // auto detect the minimum size of map.
        let mut map_size = unsafe { MAP_SIZE };
        let mut edges: Vec<ControlFlowGraphEdge> = vec![];
        // self.successor_count = vec![0; MAP_SIZE];
        // for _i in 0..MAP_SIZE {
        //     self.successor_map.push(vec![0; MAX_SUCCESSOR_COUNT]);
        // }

        // load environment variable AFL_CFG_PATH
        if let Ok(cfg_path) = std::env::var("AFL_CFG_PATH") {
            let cfg_path: &Path = Path::new(&cfg_path);
            if cfg_path.exists() {
                use alloc::string::String;
                use std::fs::File;
                use std::io::BufReader;
                let cfg_file: File = File::open(cfg_path).unwrap();
                let mut src: usize;
                let mut dst: usize;

                let mut buffer: String = String::new();
                let mut reader: BufReader<File> = BufReader::new(cfg_file);
                // while (fscanf(cfg_file, "%u %u") == 2)
                loop {
                    buffer.clear();
                    let ret: Result<usize, std::io::Error> = reader.read_line(&mut buffer);
                    if ret.is_err() {
                        break;
                    }
                    if buffer.is_empty() {
                        break;
                    }
                    let v: Vec<&str> = buffer.split_whitespace().collect();
                    if v.len() != 2 {
                        panic!("invalid cfg file");
                    }
                    assert_eq!(v.len(), 2);
                    src = v[0].parse::<usize>().unwrap();
                    dst = v[1].parse::<usize>().unwrap();

                    if src + 1 > map_size {
                        map_size = src + 1;
                    }
                    if dst + 1 > map_size {
                        map_size = dst + 1;
                    }

                    if src != dst {
                        edges.push(ControlFlowGraphEdge { src, dst });
                    }

                    // let cnt: usize = self.successor_count[src] as usize;
                    // self.successor_map[src][cnt] = dst as u32;
                    // self.successor_count[src] += 1;
                }
            } else {
                panic!("AFL_CFG_PATH not exists");
            }
        } else {
            panic!("AFL_CFG_PATH not set");
        }

        println!("Map size: {}", map_size);

        self.successor_count = vec![0; map_size];
        for _i in 0..map_size {
            self.successor_map.push(vec![0; MAX_SUCCESSOR_COUNT]);
        }

        for edge in &edges {
            let cnt: usize = self.successor_count[edge.src] as usize;
            self.successor_map[edge.src][cnt] = edge.dst as u32;
            self.successor_count[edge.src] += 1;
        }
        self.virgin_bits = vec![0xff; map_size];
        
        if map_size > unsafe { MAP_SIZE } {
            self.top_rated = vec![None; map_size];
            self.global_frontier_bitmap = Bitmap::new(map_size);
            self.global_frontier_bitmap_searched = Bitmap::new(map_size);
            self.initial_frontier_bitmap = Bitmap::new(map_size);
            self.local_covered = Bitmap::new(map_size);

            unsafe {
                MAP_SIZE = map_size;
            }
        }
    }

    /// Change scheduling method to setcover.
    fn use_setcover_schedule(&mut self) {
        if self.use_setcover_scheduling {
            return;
        }
        self.use_setcover_scheduling = true;
        self.load_cfg();
        assert!(self.successor_count.len() > 0);
        assert!(self.successor_map.len() > 0);
        // self.virgin_bits = vec![0xff; MAP_SIZE];
    }

    #[inline(always)]
    fn is_frontier_node_outer(&self, edge_id: usize) -> bool {
        let num_successors: u32 = self.successor_count[edge_id];
        if num_successors <= 1 {
            return false;
        } else {
            let mut not_visited: bool = false;

            for i in 0..num_successors {
                let successors: &Vec<u32> = &self.successor_map[edge_id];
                let succ_id: &u32 = successors.get(i as usize).unwrap();

                let succ_status = self.virgin_bits[*succ_id as usize];

                if succ_status == 0xff {
                    not_visited = true;
                    break;
                }
            }
            return not_visited;
        }
    }

    fn is_frontier_node_inner(&self, trace_bits: &Vec<u8>, edge_id: usize) -> bool {
        let num_successors: u32 = self.successor_count[edge_id];
        if num_successors <= 1 {
            return false;
        } else {
            let mut not_visited: bool = false;

            for i in 0..num_successors {
                let successors: &Vec<u32> = &self.successor_map[edge_id];
                let succ_id: &u32 = successors.get(i as usize).unwrap();

                let virgin_status: u8 = self.virgin_bits[*succ_id as usize];
                let current_status: u8 = trace_bits[*succ_id as usize];

                if virgin_status == 0xff && current_status == 0x00 {
                    not_visited = true;
                    break;
                }
            }
            return not_visited;
        }
    }

    /// Update global frontier nodes
    fn update_global_frontier_nodes(&mut self, id: CorpusId) {
        let mut updated_coverage_count: u32 = 0;
        let mut init_count: u32 = 0;

        // get number of covered frontier nodes from input
        if true {
            let input_ref: RefMut<'_, Testcase<I>> = self.corpus().get(id).unwrap().borrow_mut();
            let input: &Testcase<I> = input_ref.deref();

            init_count = input.covered_frontier_nodes_count().unwrap();
        }

        let mut count: u32 = 0;
        {
            let num_frontier_nodes: usize;
            {
                let input_ref = self.corpus().get(id).unwrap().borrow();
                num_frontier_nodes = input_ref 
                    .deref()
                    .frontier_node_bitmap()
                    .unwrap()
                    .indices
                    .len();
            }

            for i in 0..num_frontier_nodes {
                let edge_id: usize;
                // current is true.
                {
                    let input_ref = self.corpus().get(id).unwrap().borrow();
                    edge_id = input_ref 
                        .deref()
                        .frontier_node_bitmap()
                        .unwrap()
                        .indices[i];
                }
    
                if !self.is_frontier_node_outer(edge_id) {
                    count += 1;
                    if self.global_frontier_bitmap.get(edge_id) {
                        self.global_frontier_bitmap.clear(edge_id);
                    }
    
                    // clear the bit from bitmap since it is no longer frontier node.
                    {
                        let mut input_ref: RefMut<'_, Testcase<I>> =
                            self.corpus().get(id).unwrap().borrow_mut();
                        input_ref
                            .deref_mut()
                            .frontier_node_bitmap_mut()
                            .unwrap()
                            .clear(edge_id);
                    }
                }
                updated_coverage_count += 1;
            }
        }

        // q->covered_frontier_nodes_count = updated_coverage_count;
        if true {
            let mut input_ref: RefMut<'_, Testcase<I>> =
                self.corpus().get(id).unwrap().borrow_mut();
            let _res: Result<(), Error> = input_ref
                .deref_mut()
                .set_covered_frontier_nodes_count(updated_coverage_count);
        }
        if self.global_frontier_bitmap.popcount() == 0 {
            println!(
                "Seed id {}, initial count {}, count {}",
                id, init_count, count
            );
            panic!("global_covered_frontier_nodes_count is 0");
        }
    }

    /// Perform seed reduction.
    fn setcover_reduction(&mut self) {
        assert!(self.use_setcover_scheduling);

        unsafe {
            if !FAVORED_CORPUS.is_empty() {
                if !MAP_CHANGED {
                    let selected_id: CorpusId = FAVORED_CORPUS.pop().unwrap();
                    let _ret: Result<(), Error> = self.corpus_mut().set_favored_id(selected_id);
                    // self.update_global_frontier_nodes(selected_id);
                    return;
                } else {
                    // dicards previous selected seeds.
                    FAVORED_CORPUS.clear();
                    MAP_CHANGED = false;
                }
            }
        }

        let real_map_size = self.global_frontier_bitmap.len();
        for i in 0..real_map_size {
            if self.global_frontier_bitmap.get(i) {
                if !self.is_frontier_node_outer(i) {
                    self.global_frontier_bitmap.clear(i);
                }
            }
        }

        self.local_covered.clear_all();
        if self.corpus().is_empty() {
            panic!("No seeds in corpus");
        }
        let popcount_global_frontier_bitmap: usize = self.global_frontier_bitmap.popcount();

        let mut fast_seed_exist: bool = false;
        let mut fast_seed_count: usize = 0;
        let mut set_covered_seed_list: Vec<CorpusId> = vec![];

        let mut unselected_seeds: Vec<CorpusId> = vec![];
        let mut all_seeds: Vec<CorpusId> = vec![];

        let mut unselected_seeds_count: u32 = 0;

        let mut total_exec_us: f64 = 0.0;
        let mut total_exec_us_sq: f64 = 0.0;
        let mut max_exec_us: f64 = 0.0;

        use core::ops::Deref;

        for it in self.corpus().ids() {
            all_seeds.push(it);
        }

        if true {
            use rand::seq::SliceRandom;
            all_seeds.shuffle(&mut rand::thread_rng());
        }

        // compute execution time statistics,
        // and count the number of seeds
        for it in &all_seeds {
            // self.update_global_frontier_nodes(*it);

            let input_ref: Ref<'_, Testcase<I>> = self.corpus().get(*it).unwrap().borrow();

            let input: &Testcase<I> = input_ref.deref();

            let mut exec_time_us: f64 = DEFAULT_EXEC_TIME_US;
            let exec_time: &Option<Duration> = input.exec_time();
            if exec_time != &None {
                exec_time_us = exec_time.unwrap().as_micros() as f64;
            } else {
                // use default value
            }

            total_exec_us += exec_time_us;
            total_exec_us_sq += exec_time_us * exec_time_us;
            max_exec_us = max_exec_us.max(exec_time_us);

            let covered_frontier_nodes_count = input.covered_frontier_nodes_count().unwrap();

            if covered_frontier_nodes_count > 0 {
                unselected_seeds_count += 1;
                unselected_seeds.push(*it);
            }
        }

        // compute mean and standard deviation
        let corpus_count_f: f64 = self.corpus().count() as f64;
        let mean_exec_us: f64 = (total_exec_us - max_exec_us) / (corpus_count_f - 1.0);
        let stddev_exec_us_sq: f64 =
            total_exec_us_sq / corpus_count_f - mean_exec_us * mean_exec_us;
        let stddev_exec_us: f64 = stddev_exec_us_sq.sqrt();

        if unselected_seeds_count == 0 {
            // randomly select one from all seeds.
            let _ret: Result<(), Error> = self.corpus_mut().set_favored_id(all_seeds.pop().unwrap());
            unsafe {
                FAVORED_CORPUS.extend_from_slice(all_seeds.as_slice());
            }
        } else {
            assert_eq!(unselected_seeds_count, unselected_seeds.len() as u32);

            let mut covered_not_searched_seeds: Vec<CorpusId> = vec![];

            while unselected_seeds_count > 0 {
                // randomly sample a seed.
                // for unselected seeds are already shuffled,
                // we can just use the last one.
                let random_idx: usize = (unselected_seeds_count - 1) as usize;
                let seed_index: CorpusId = unselected_seeds[random_idx];
                let mut exec_time: f64 = DEFAULT_EXEC_TIME_US;
                let mut covered_unsearched = false;

                // compute execution time, use default value if not available.
                if true {
                    let seed_ref: Ref<'_, Testcase<I>> =
                        self.corpus().get(seed_index).unwrap().borrow();
                    let reduction_seed: &Testcase<I> = seed_ref.deref();

                    let exec_time_opt: &Option<Duration> = reduction_seed.exec_time();
                    if exec_time_opt != &None {
                        exec_time = exec_time_opt.unwrap().as_micros() as f64;
                    }
                }

                // decrement size of unselected seeds,
                // move the last element to the current position.
                unselected_seeds_count -= 1;

                let mut local_covered_intersection_num: u32 = 0;
                // compute local_covered_intersection_num.
                if true {
                    let mut len: usize = 0;
                    if true {
                        let local_covered: &mut Bitmap = &mut self.local_covered;
                        len = local_covered.len();
                    }
                    assert_ne!(len, 0);

                    let frontier_node_bitmap: Vec<usize>;
                    {
                        let seed_ref: Ref<'_, Testcase<I>> =
                                self.corpus().get(seed_index).unwrap().borrow();
                        let reduction_seed: &Testcase<I> = seed_ref.deref();    
                        frontier_node_bitmap = reduction_seed.frontier_node_bitmap().unwrap().indices.clone();
                    }

                    for edge in frontier_node_bitmap {
                        // mark this frontier node as covered. 
                        let previous = self.local_covered.get(edge);

                        // should also check whether `edge` is a frontier node.
                        if !previous && self.global_frontier_bitmap.get(edge) {
                            self.local_covered.set(edge);
                            local_covered_intersection_num += 1;

                            if !self.global_frontier_bitmap_searched.get(edge) {
                                self.global_frontier_bitmap_searched.set(edge);
                                covered_unsearched = true;
                            }
                        }
                    }

                }

                if local_covered_intersection_num == 0 {
                    // the seed does not bring new coverage.
                    // skip
                    continue;
                }

                // record in the seed list and fast seed list.
                set_covered_seed_list.push(seed_index);
                if exec_time < mean_exec_us + 1.0 * stddev_exec_us {
                    fast_seed_exist = true;
                    fast_seed_count += 1;
                }

                if covered_unsearched {
                    covered_not_searched_seeds.push(seed_index);
                }

                // check whether all frontier nodes are covered.
                let mut all_covered: bool = true;

                if true {
                    let local_covered: &mut Bitmap = &mut self.local_covered;
                    // for j in 0..local_covered.len() / 8 {
                    //     let local: u8 = local_covered.get_ubyte(j);
                    //     let global: u8 = self.global_frontier_bitmap.get_ubyte(j);
                    //     if (!local) & global == 0 {
                    //         all_covered = false;
                    //         break;
                    //     }
                    // }
                    
                    // Optimization from O(L) to O(1):
                    // if the popcount of local_coverd is less than popcount of global_frontier_bitmap,
                    // then all_covered cannot be true.
                    if local_covered.popcount() < popcount_global_frontier_bitmap {
                        all_covered = false;
                    }
                }

                // update the number of fast seeds.
                if fast_seed_exist {
                    self.corpus_mut().set_fast(fast_seed_count);
                } else {
                    self.corpus_mut().set_fast(0);
                }
                if all_covered || unselected_seeds_count == 0 {
                    unsafe {
                        if covered_not_searched_seeds.is_empty() {
                            FAVORED_CORPUS.extend_from_slice(set_covered_seed_list.as_slice());
                        } else {
                            FAVORED_CORPUS.extend_from_slice(covered_not_searched_seeds.as_slice());
                        }
                    }

                    unsafe {
                        let _ret = self.corpus_mut().set_favored_id(FAVORED_CORPUS.pop().unwrap());
                    }
                    break;
                }
            }
        }
    }

    /// Update bitmap score.
    fn update_bitmap_score(&mut self, trace_bits: Vec<u8>, id: CorpusId) {
        let trace_len: usize = trace_bits.len();
        // println!("Trace bits {}", trace_bits.len());

        for i in 0..trace_len {
            let bit: u8 = trace_bits[i];
            if bit != 0 {
                let edge_id: usize = i;

                if self.is_frontier_node_inner(&trace_bits, edge_id) {
                    // update this edge.
                    if true {
                        let mut input_ref: RefMut<'_, Testcase<I>> =
                            self.corpus().get(id).unwrap().borrow_mut();

                        let input: &mut Testcase<I> = input_ref.deref_mut();

                        let frontier_bitmap: &mut SparseBitmap =
                            input.frontier_node_bitmap_mut().unwrap();
                        frontier_bitmap.set(edge_id);

                        let nodes_count: u32 = input.covered_frontier_nodes_count().unwrap();
                        let _res: Result<(), Error> =
                            input.set_covered_frontier_nodes_count(nodes_count + 1);
                    }

                    // update global frontier bitmap.
                    if true {
                        let global_frontier_bitmap: &mut Bitmap = &mut self.global_frontier_bitmap;
                        if !global_frontier_bitmap.get(edge_id) {
                            global_frontier_bitmap.set(edge_id);
                            unsafe { MAP_CHANGED = true };
                        }
                    }
                }

                self.top_rated[i] = Some(id);
                self.score_changed = true;
            }
        }
    }

    /// Go over top rated entries and sequentially grab
    /// winners for previously unseen bytes and marks
    /// them as favored.
    fn cull_queue(&mut self) {
        self.setcover_reduction();
    }
}

impl StdState<NopInput, InMemoryCorpus<NopInput>, StdRand, InMemoryCorpus<NopInput>> {
    /// Create an empty [`StdState`] that has very minimal uses.
    /// Potentially good for testing.
    pub fn nop<I>() -> Result<StdState<I, InMemoryCorpus<I>, StdRand, InMemoryCorpus<I>>, Error>
    where
        I: Input,
    {
        StdState::new(
            StdRand::with_seed(0),
            InMemoryCorpus::<I>::new(),
            InMemoryCorpus::new(),
            &mut (),
            &mut (),
        )
    }
}

#[cfg(feature = "introspection")]
impl<I, C, R, SC> HasClientPerfMonitor for StdState<I, C, R, SC> {
    fn introspection_monitor(&self) -> &ClientPerfMonitor {
        &self.introspection_monitor
    }

    fn introspection_monitor_mut(&mut self) -> &mut ClientPerfMonitor {
        &mut self.introspection_monitor
    }
}

#[cfg(feature = "scalability_introspection")]
impl<I, C, R, SC> HasScalabilityMonitor for StdState<I, C, R, SC> {
    fn scalability_monitor(&self) -> &ScalabilityMonitor {
        &self.scalability_monitor
    }

    fn scalability_monitor_mut(&mut self) -> &mut ScalabilityMonitor {
        &mut self.scalability_monitor
    }
}

/// A very simple state without any bells or whistles, for testing.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct NopState<I> {
    metadata: SerdeAnyMap,
    execution: u64,
    stop_requested: bool,
    rand: StdRand,
    phantom: PhantomData<I>,
}

impl<I> NopState<I> {
    /// Create a new State that does nothing (for tests)
    #[must_use]
    pub fn new() -> Self {
        NopState {
            metadata: SerdeAnyMap::new(),
            execution: 0,
            rand: StdRand::default(),
            stop_requested: false,
            phantom: PhantomData,
        }
    }
}

impl<I> HasMaxSize for NopState<I> {
    fn max_size(&self) -> usize {
        16_384
    }

    fn set_max_size(&mut self, _max_size: usize) {
        unimplemented!("NopState doesn't allow setting a max size")
    }
}

impl<I> UsesInput for NopState<I>
where
    I: Input,
{
    type Input = I;
}

impl<I> HasExecutions for NopState<I> {
    fn executions(&self) -> &u64 {
        &self.execution
    }

    fn executions_mut(&mut self) -> &mut u64 {
        &mut self.execution
    }
}

impl<I> Stoppable for NopState<I> {
    fn request_stop(&mut self) {
        self.stop_requested = true;
    }

    fn discard_stop_request(&mut self) {
        self.stop_requested = false;
    }

    fn stop_requested(&self) -> bool {
        self.stop_requested
    }
}

impl<I> HasLastReportTime for NopState<I> {
    fn last_report_time(&self) -> &Option<Duration> {
        unimplemented!();
    }

    fn last_report_time_mut(&mut self) -> &mut Option<Duration> {
        unimplemented!();
    }
}

impl<I> HasMetadata for NopState<I> {
    fn metadata_map(&self) -> &SerdeAnyMap {
        &self.metadata
    }

    fn metadata_map_mut(&mut self) -> &mut SerdeAnyMap {
        &mut self.metadata
    }
}

impl<I> HasRand for NopState<I> {
    type Rand = StdRand;

    fn rand(&self) -> &Self::Rand {
        &self.rand
    }

    fn rand_mut(&mut self) -> &mut Self::Rand {
        &mut self.rand
    }
}

impl<I> State for NopState<I> where I: Input {}

impl<I> HasCurrentCorpusId for NopState<I> {
    fn set_corpus_id(&mut self, _id: CorpusId) -> Result<(), Error> {
        Ok(())
    }

    fn clear_corpus_id(&mut self) -> Result<(), Error> {
        Ok(())
    }

    fn current_corpus_id(&self) -> Result<Option<CorpusId>, Error> {
        Ok(None)
    }
}

impl<I> HasCurrentStageId for NopState<I> {
    fn set_current_stage_id(&mut self, _idx: StageId) -> Result<(), Error> {
        Ok(())
    }

    fn clear_stage_id(&mut self) -> Result<(), Error> {
        Ok(())
    }

    fn current_stage_id(&self) -> Result<Option<StageId>, Error> {
        Ok(None)
    }
}

#[cfg(feature = "introspection")]
impl<I> HasClientPerfMonitor for NopState<I> {
    fn introspection_monitor(&self) -> &ClientPerfMonitor {
        unimplemented!();
    }

    fn introspection_monitor_mut(&mut self) -> &mut ClientPerfMonitor {
        unimplemented!();
    }
}

#[cfg(feature = "scalability_introspection")]
impl<I> HasScalabilityMonitor for NopState<I> {
    fn scalability_monitor(&self) -> &ScalabilityMonitor {
        unimplemented!();
    }

    fn scalability_monitor_mut(&mut self) -> &mut ScalabilityMonitor {
        unimplemented!();
    }
}

#[cfg(test)]
mod test {
    use crate::{inputs::BytesInput, state::StdState};
    use crate::bitmap::BitmapTrait;

    #[test]
    fn test_std_state() {
        StdState::nop::<BytesInput>().expect("couldn't instantiate the test state");
    }

    #[test]
    fn test_load_cfg() {
        // create a fake cfg file.
        use crate::state::HasSetCover;
        use std::io::Write;

        use crate::state::MAP_SIZE;
        let fname: &str = "/tmp/tmp_cfg";
        let mut fobj: std::fs::File = std::fs::File::create(fname).unwrap();
        let _ = fobj.write_all(b"0 1\n");
        let _ = fobj.write_all(b"6  5\n");
        let _ = fobj.sync_all();

        // check that the loadcfg works
        let mut state: StdState<BytesInput, _, _, _> =
            StdState::nop::<BytesInput>().expect("couldn't instantiate the test state");
        
        let mut map_size: usize = unsafe { MAP_SIZE };
        assert_eq!(state.global_frontier_bitmap.len(), map_size);
        assert_eq!(state.initial_frontier_bitmap.len(), map_size);
        assert_eq!(state.local_covered.len(), map_size);

        let key: &str = "AFL_CFG_PATH";
        let old_cfg_path = std::env::var(key);
        std::env::set_var(key, fname);

        state.use_setcover_schedule();
        map_size = unsafe { MAP_SIZE };
        assert!(state.use_setcover_scheduling);
        assert!(state.virgin_bits.len() == map_size);
        assert_eq!(state.successor_count[0], 1);
        assert_eq!(state.successor_count[6], 1);
        assert_eq!(state.successor_map[0][0], 1);
        assert_eq!(state.successor_map[6][0], 5);

        // recover old env var
        if old_cfg_path.is_ok() {
            std::env::set_var(key, old_cfg_path.unwrap());
        } else {
            std::env::remove_var(key);
        }

        // remove the temporay file.
        std::fs::remove_file(fname).unwrap();
    }

    #[test]
    fn test_load_cfg_2() {
        // create a fake cfg file.
        use crate::state::HasSetCover;
        use std::io::Write;
        use crate::state::MAP_SIZE;

        let fname: &str = "/tmp/tmp_cfg2";
        let mut fobj: std::fs::File = std::fs::File::create(fname).unwrap();
        let _ = fobj.write_all(b"0 1\n");
        let _ = fobj.write_all(b"32768  65535\n");
        let _ = fobj.sync_all();

        let expected_map_size: usize = 65536;
        
        // check that the loadcfg works
        let mut state: StdState<BytesInput, _, _, _> =
            StdState::nop::<BytesInput>().expect("couldn't instantiate the test state");
        let map_size = unsafe { MAP_SIZE };
        assert_eq!(state.global_frontier_bitmap.len(), map_size);
        assert_eq!(state.initial_frontier_bitmap.len(), map_size);
        assert_eq!(state.local_covered.len(), map_size);

        let key: &str = "AFL_CFG_PATH";
        let old_cfg_path = std::env::var(key);
        std::env::set_var(key, fname);

        state.use_setcover_schedule();
        assert!(state.use_setcover_scheduling);

        // check that the map size is correct.
        assert_eq!(state.global_frontier_bitmap.len(), expected_map_size);
        assert_eq!(state.initial_frontier_bitmap.len(), expected_map_size);
        assert_eq!(state.local_covered.len(), expected_map_size);
        assert!(state.virgin_bits.len() == expected_map_size);

        // check the control flow graph.
        assert_eq!(state.successor_count[0], 1);
        assert_eq!(state.successor_count[32768], 1);
        assert_eq!(state.successor_map[0][0], 1);
        assert_eq!(state.successor_map[32768][0], 65535);

        // recover old env var
        if old_cfg_path.is_ok() {
            std::env::set_var(key, old_cfg_path.unwrap());
        } else {
            std::env::remove_var(key);
        }

        // remove the temporay file.
        std::fs::remove_file(fname).unwrap();
    }
}
