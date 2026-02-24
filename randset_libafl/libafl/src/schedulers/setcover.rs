//! The setcover scheduler.

use core::ops::DerefMut;
use std::borrow::ToOwned;

use crate::{
    corpus::{Corpus, CorpusId},
    observers::MapObserver,
    schedulers::{RemovableScheduler, Scheduler},
    state::{HasCorpus, HasSetCover},
    Error,
};
use libafl_bolts::ErrorBacktrace;

use super::HasQueueCycles;

/// The setcover scheduler.
#[derive(Debug, Clone)]
pub struct SetcoverScheduler<O> {
    // The number of cycles fuzzed.
    num_cycles: u64,
    // The observer.
    observer: *const O,
}

impl<I, S, O> RemovableScheduler<I, S> for SetcoverScheduler<O> {}

impl<O> SetcoverScheduler<O>
where
    O: MapObserver<Entry = u8> + Clone,
{
    /// Creates a new [`SetcoverScheduler`].
    pub fn new(observer: &O) -> Self {
        Self {
            num_cycles: 0,
            observer: observer,
        }
    }
}

impl<I, S, O> Scheduler<I, S> for SetcoverScheduler<O>
where
    S: HasCorpus + HasSetCover,
    O: MapObserver<Entry = u8> + Clone,
{
    fn on_add(&mut self, state: &mut S, id: CorpusId) -> Result<(), Error> {
        // Set parent id
        if true {
            let current_id: Option<CorpusId> = *state.corpus().current();

            let mut input_ref: core::cell::RefMut<
                '_,
                crate::corpus::Testcase<<<S as HasCorpus>::Corpus as Corpus>::Input>,
            > = state.corpus().get(id).unwrap().borrow_mut();

            let input = input_ref.deref_mut();

            match input.use_setcover_schedule() {
                Ok(()) => {}
                Err(_) => {
                    return Err(Error::empty(
                        "Input already has a setcover schedule.".to_owned(),
                    ));
                }
            }
            input.set_parent_id_optional(current_id);
        }

        // when we bump into a new path, we call update_bitmap_score()
        // to see if the path appears more favorable than existing ones.
        if true {
            state.update_bitmap_score(unsafe { self.observer.as_ref().unwrap().to_vec() }, id);
        }
        return Ok(());
    }

    fn next(&mut self, state: &mut S) -> Result<CorpusId, Error> {
        self.num_cycles += 1;
        if state.corpus().count() == 0 {
            return Err(Error::empty(
                "No entries in corpus. This often implies the target is not properly instrumented."
                    .to_owned(),
            ));
        } else {
            // select next seed.
            state.cull_queue();

            // try to get the favored id.
            let mut id = state.corpus().get_favored_id();

            if id == None {
                // use next id.
                let default_id = state
                    .corpus()
                    .current()
                    .map(|id| state.corpus().next(id))
                    .flatten()
                    .unwrap_or_else(|| state.corpus().first().unwrap());

                id = Some(default_id);
            }

            <Self as Scheduler<I, S>>::set_current_scheduled(self, state, id)?;
            return Ok(id.unwrap());
        }
    }

    fn set_current_scheduled(
        &mut self,
        state: &mut S,
        next_id: Option<CorpusId>,
    ) -> Result<(), Error> {
        if next_id == None {
            return Err(Error::Empty(
                "No next id provided.".to_owned(),
                ErrorBacktrace::new(),
            ));
        } else {
            *state.corpus_mut().current_mut() = next_id;
            return Ok(());
        }
    }
}

impl<O> HasQueueCycles for SetcoverScheduler<O> {
    fn queue_cycles(&self) -> u64 {
        return self.num_cycles;
    }
}

impl<O> Default for SetcoverScheduler<O>
where
    O: MapObserver<Entry = u8> + Clone,
{
    fn default() -> Self {
        Self {
            num_cycles: 0,
            observer: std::ptr::null(), // nullptr
        }
    }
}
