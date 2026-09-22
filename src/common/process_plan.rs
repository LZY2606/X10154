// Take a look at the license at the top of the repository in the file.

//! Platform-independent normalization of a process refresh request into an immutable execution
//! plan.
//!
//! Every OS adapter performs the same kind of decision taking before touching the system:
//!  * does the request concern every process or a fixed set of PIDs?
//!  * are non-existent PIDs discoverable (`All`) or merely marked as dead (`Some`)?
//!  * is enough time elapsed to compute a new CPU usage sample?
//!  * which of the requested fields can the platform actually provide?
//!
//! Doing this reasoning once, in pure code, means extending [`ProcessRefreshKind`] or
//! [`ProcessesToUpdate`] only requires updating this module instead of every OS module. OS
//! adapters consume the resulting [`ProcessRefreshPlan`] and limit themselves to collecting data
//! and applying it to the process map; they never re-interpret the request.

use crate::Pid;
use crate::{ProcessRefreshKind, ProcessesToUpdate, UpdateKind};

use std::collections::BTreeSet;
use std::time::Duration;

bitflags::bitflags! {
    /// Fields a platform can never provide for a [`crate::Process`].
    ///
    /// A field being listed here does **not** mean the platform returns a fake zero value for it:
    /// adapters must leave the corresponding value untouched (or absent) so that users can rely on
    /// [`Option`] returning [`None`]. The set only documents the platform gap explicitly and lets
    /// the plan avoid issuing useless system calls.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct UnsupportedFields: u16 {
        /// `Process::user_id` and friends.
        const USER = 1 << 0;
        /// `Process::cwd`.
        const CWD = 1 << 1;
        /// `Process::root`.
        const ROOT = 1 << 2;
        /// `Process::environ`.
        const ENVIRON = 1 << 3;
        /// `Process::cmd`.
        const CMD = 1 << 4;
        /// `Process::exe`.
        const EXE = 1 << 5;
        /// `Process::disk_usage`.
        const DISK_USAGE = 1 << 6;
        /// Process tasks (only meaningful on Linux).
        const TASKS = 1 << 7;
        /// `Process::gpu_usage`.
        const GPU_USAGE = 1 << 8;
        /// `Process::gpu_memory`.
        const GPU_MEMORY = 1 << 9;
    }
}

/// Static description of what an OS adapter is able to collect.
///
/// Every supported platform provides exactly one of these. Adding a new platform requires
/// constructing it as well: the platform capability mapping is exercised by
/// [`crate::sys::PROCESS_CAPABILITIES`] and the `check_process_capabilities` test guard.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessCapabilities {
    /// Fields that cannot be collected on this platform.
    pub unsupported: UnsupportedFields,
    /// Minimum elapsed time between two CPU usage samples.
    pub minimum_cpu_update_interval: Duration,
}

impl ProcessCapabilities {
    /// Capabilities of a platform that collects everything and has no CPU sampling throttling.
    pub const FULL: Self = Self {
        unsupported: UnsupportedFields::empty(),
        minimum_cpu_update_interval: Duration::ZERO,
    };
}

/// Normalized, deduplicated description of which processes an adapter must visit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProcessSelection {
    /// Enumerate the processes currently visible to the system.
    ///
    /// Newly discovered PIDs must be inserted into the process map.
    DiscoverAll,
    /// Visit exactly the listed, already deduplicated PIDs.
    ///
    /// PIDs that cannot be collected are *not* inserted: they are simply reported as not updated.
    /// The plan keeps the original order semantics by storing a set; callers never rely on order
    /// when refreshing.
    ExactPids(BTreeSet<Pid>),
}

impl ProcessSelection {
    /// Returns `true` if every process of the system must be enumerated.
    pub fn is_all(&self) -> bool {
        matches!(self, Self::DiscoverAll)
    }

    /// Returns the explicit PID list if the selection is [`ProcessSelection::ExactPids`].
    pub fn pids(&self) -> Option<&BTreeSet<Pid>> {
        match self {
            Self::DiscoverAll => None,
            Self::ExactPids(pids) => Some(pids),
        }
    }
}

/// What an adapter should do with CPU data during the collection phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CpuSampling {
    /// CPU information is not part of the request.
    ///
    /// Raw accumulated times can still be recorded when they come for free with another field,
    /// but no CPU usage must be computed and no CPU sampling timestamp must be touched.
    NotRequested,
    /// This is the first sample for the system: raw times have to be stored but the resulting
    /// usage must stay at its previous value (usually `0`).
    FirstSample,
    /// The last sample is too recent: store the new raw times without producing a new usage value.
    IntervalTooShort,
    /// Enough time elapsed since the previous sample: a real delta can be computed.
    Ready,
}

impl CpuSampling {
    /// Returns `true` if raw CPU times should be collected.
    pub fn collect_raw_times(self) -> bool {
        !matches!(self, Self::NotRequested)
    }

    /// Returns `true` if a CPU usage delta can be computed from the fresh raw times.
    pub fn compute_usage(self) -> bool {
        matches!(self, Self::Ready)
    }
}

/// Information about the previous CPU sample, used to decide whether a new sample is meaningful.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PreviousCpuSample {
    /// Elapsed time since the last CPU sample, or [`None`] if no sample ever happened.
    pub elapsed: Option<Duration>,
}

/// Immutable execution plan consumed by OS adapters.
///
/// Built from the public request types through [`ProcessRefreshPlan::new`]. Adapters must not
/// construct or mutate it: the fields are only exposed for reading.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessRefreshPlan {
    selection: ProcessSelection,
    kind: ProcessRefreshKind,
    effective_kind: ProcessRefreshKind,
    remove_dead: bool,
    unsupported: UnsupportedFields,
    cpu_sampling: CpuSampling,
    minimum_cpu_update_interval: Duration,
}

impl ProcessRefreshPlan {
    /// Normalizes a refresh request into a plan.
    ///
    /// Parameters:
    ///  * `processes_to_update`: the public all/some selection.
    ///  * `remove_dead_processes`: whether PIDs visited but not refreshed must be removed during
    ///    the commit phase.
    ///  * `refresh_kind`: which fields the user asked for.
    ///  * `capabilities`: what the running platform can provide and its CPU sampling interval.
    ///  * `previous`: state of the previous system-wide CPU sample.
    pub fn new(
        processes_to_update: ProcessesToUpdate<'_>,
        remove_dead_processes: bool,
        refresh_kind: ProcessRefreshKind,
        capabilities: ProcessCapabilities,
        previous: PreviousCpuSample,
    ) -> Self {
        let selection = match processes_to_update {
            ProcessesToUpdate::All => ProcessSelection::DiscoverAll,
            ProcessesToUpdate::Some(pids) => {
                ProcessSelection::ExactPids(pids.iter().copied().collect())
            }
        };

        let unsupported = capabilities.unsupported;
        let effective_kind = mask_supported(refresh_kind, unsupported);

        let cpu_sampling = if !refresh_kind.cpu() {
            CpuSampling::NotRequested
        } else {
            match previous.elapsed {
                None => CpuSampling::FirstSample,
                Some(elapsed) if elapsed < capabilities.minimum_cpu_update_interval => {
                    CpuSampling::IntervalTooShort
                }
                Some(_) => CpuSampling::Ready,
            }
        };

        Self {
            selection,
            kind: refresh_kind,
            effective_kind,
            remove_dead: remove_dead_processes,
            unsupported,
            cpu_sampling,
            minimum_cpu_update_interval: capabilities.minimum_cpu_update_interval,
        }
    }

    /// Normalized process selection (deduplicated, `All` vs explicit PIDs).
    pub fn selection(&self) -> &ProcessSelection {
        &self.selection
    }

    /// The refresh kind exactly as requested by the user, before capability masking.
    pub fn requested_kind(&self) -> ProcessRefreshKind {
        self.kind
    }

    /// The refresh kind with unsupported fields switched off.
    ///
    /// Adapters must drive their collection from this value: it guarantees they never try to
    /// fetch data the platform cannot provide and never invent a zero value to fake success.
    pub fn refresh_kind(&self) -> ProcessRefreshKind {
        self.effective_kind
    }

    /// Whether dead processes visited during collection must be removed in the commit phase.
    pub fn remove_dead_processes(&self) -> bool {
        self.remove_dead
    }

    /// Fields the platform explicitly cannot provide.
    pub fn unsupported_fields(&self) -> UnsupportedFields {
        self.unsupported
    }

    /// How CPU data must be handled for this refresh.
    pub fn cpu_sampling(&self) -> CpuSampling {
        self.cpu_sampling
    }

    /// Minimum interval between two CPU usage samples on the platform.
    pub fn minimum_cpu_update_interval(&self) -> Duration {
        self.minimum_cpu_update_interval
    }

    /// Returns `true` if the adapter should iterate at least one process.
    ///
    /// An empty explicit selection means there is nothing to collect and the adapter can return
    /// `0` immediately without performing any system call, matching the historical behavior of
    /// every platform.
    pub fn is_empty(&self) -> bool {
        matches!(&self.selection, ProcessSelection::ExactPids(pids) if pids.is_empty())
    }
}

/// Disables every requested field that belongs to `unsupported`.
fn mask_supported(
    kind: ProcessRefreshKind,
    unsupported: UnsupportedFields,
) -> ProcessRefreshKind {
    let mut out = kind;
    if unsupported.contains(UnsupportedFields::USER) {
        out = out.without_user();
    }
    if unsupported.contains(UnsupportedFields::CWD) {
        out = out.without_cwd();
    }
    if unsupported.contains(UnsupportedFields::ROOT) {
        out = out.without_root();
    }
    if unsupported.contains(UnsupportedFields::ENVIRON) {
        out = out.without_environ();
    }
    if unsupported.contains(UnsupportedFields::CMD) {
        out = out.without_cmd();
    }
    if unsupported.contains(UnsupportedFields::EXE) {
        out = out.without_exe();
    }
    if unsupported.contains(UnsupportedFields::DISK_USAGE) {
        out = out.without_disk_usage();
    }
    if unsupported.contains(UnsupportedFields::TASKS) {
        out = out.without_tasks();
    }
    if unsupported.contains(UnsupportedFields::GPU_USAGE) {
        out = out.without_gpu_usage();
    }
    if unsupported.contains(UnsupportedFields::GPU_MEMORY) {
        out = out.without_gpu_memory();
    }
    out
}

// `UpdateKind` re-export keeps the plan module the single place documenting how the public
// request types map to the execution plan.
pub(crate) use UpdateKind as _UpdateKindMarker;

#[cfg(test)]
mod tests;
