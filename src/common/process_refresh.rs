// Take a look at the license at the top of the repository in the LICENSE file.

//! Platform-independent normalization of process refresh requests.
//!
//! Each OS used to independently re-interpret the combination of
//! [`ProcessRefreshKind`], [`ProcessesToUpdate`], the previous CPU sampling state and its own
//! capabilities. This module turns that combination into a single, immutable
//! [`ProcessRefreshPlan`]. OS adapters only collect what the plan asks for and report
//! per-process [`Outcome`]s; this module stays free of any real system call.

use crate::{Pid, ProcessRefreshKind, ProcessesToUpdate, UpdateKind};

use std::time::{Duration, Instant};

/// The complete, immutable execution plan of one
/// [`System::refresh_processes_specifics`](crate::System::refresh_processes_specifics) call.
///
/// It is built once by [`ProcessRefreshPlan::new`] from the public request, the previous CPU
/// sampling state and the platform [`ProcessCapabilities`]. It contains no system state and
/// never performs any system call.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ProcessRefreshPlan {
    selection: ProcessSelection,
    cpu: CpuPlan,
    dead_processes: DeadProcessPolicy,
    discover_new_processes: bool,
    fields: FieldPlan,
    capabilities: ProcessCapabilities,
}

impl ProcessRefreshPlan {
    /// Normalizes a refresh request into an immutable plan.
    ///
    /// * `kind` is the public [`ProcessRefreshKind`].
    /// * `processes_to_update` keeps the `all`/`some` distinction (and, for `some`, the exact
    ///   requested PID list, including empty lists and duplicates).
    /// * `remove_dead_processes` tells whether processes reported as dead must be removed.
    /// * `sampling` carries the previous system-wide CPU sampling instant (if any) and the
    ///   platform minimum interval between two CPU samples.
    /// * `capabilities` describes what the platform can actually retrieve.
    ///
    /// Fields requested by `kind` but unsupported by the platform are kept as
    /// [`FieldFetch::Unsupported`] instead of being silently treated as successful empty
    /// values.
    pub(crate) fn new(
        kind: ProcessRefreshKind,
        processes_to_update: ProcessesToUpdate<'_>,
        remove_dead_processes: bool,
        sampling: CpuSamplingContext,
        capabilities: ProcessCapabilities,
    ) -> Self {
        let selection = ProcessSelection::from_request(processes_to_update);
        Self {
            discover_new_processes: true,
            dead_processes: DeadProcessPolicy::new(remove_dead_processes),
            cpu: CpuPlan::new(kind, sampling),
            fields: FieldPlan::new(kind, capabilities),
            selection,
            capabilities,
        }
    }

    /// The normalized process selection (`all` or `some`).
    pub(crate) fn selection(&self) -> ProcessSelection {
        self.selection
    }

    /// The CPU sampling plan, which carries the minimum interval and the first/second sample
    /// decision.
    pub(crate) fn cpu(&self) -> CpuPlan {
        self.cpu
    }

    /// How dead processes must be handled during the commit phase.
    pub(crate) fn dead_processes(&self) -> DeadProcessPolicy {
        self.dead_processes
    }

    /// Whether processes discovered while collecting but not tracked yet must be added.
    ///
    /// Both `all` and `some` selections discover new processes; `some` only discovers the
    /// requested PIDs.
    pub(crate) fn discover_new_processes(&self) -> bool {
        self.discover_new_processes
    }

    /// The platform capabilities this plan was built with.
    pub(crate) fn capabilities(&self) -> ProcessCapabilities {
        self.capabilities
    }

    /// The plan for a single optional (update kind) field.
    pub(crate) fn field(&self, field: ProcessField) -> FieldFetch {
        self.fields.fetch(field)
    }

    /// Returns `true` if a boolean-like field must be collected.
    fn bool_field(&self, field: ProcessField) -> bool {
        self.fields.fetch(field) == FieldFetch::Collect
    }

    /// Whether memory information must be collected.
    pub(crate) fn memory(&self) -> bool {
        self.bool_field(ProcessField::Memory)
    }

    /// Whether disk activity must be collected.
    pub(crate) fn disk_usage(&self) -> bool {
        self.bool_field(ProcessField::DiskUsage)
    }

    /// Whether Linux tasks must be enumerated.
    pub(crate) fn tasks(&self) -> bool {
        self.bool_field(ProcessField::Tasks)
    }

    /// Whether GPU usage must be collected.
    pub(crate) fn gpu_usage(&self) -> bool {
        self.bool_field(ProcessField::GpuUsage)
    }

    /// Whether GPU memory must be collected.
    pub(crate) fn gpu_memory(&self) -> bool {
        self.bool_field(ProcessField::GpuMemory)
    }

    /// Effective decision for an optional field, collapsing
    /// [`FieldFetch::Unsupported`] into [`UpdateKind::Never`] so adapters can pass it to
    /// [`UpdateKind::needs_update`].
    pub(crate) fn update_kind(&self, field: ProcessField) -> UpdateKind {
        match self.fields.fetch(field) {
            FieldFetch::Unsupported => UpdateKind::Never,
            FieldFetch::Skip => UpdateKind::Never,
            FieldFetch::CollectIfNotSet => UpdateKind::OnlyIfNotSet,
            FieldFetch::AlwaysCollect => UpdateKind::Always,
        }
    }

    pub(crate) fn user(&self) -> UpdateKind {
        self.update_kind(ProcessField::User)
    }

    pub(crate) fn cwd(&self) -> UpdateKind {
        self.update_kind(ProcessField::Cwd)
    }

    pub(crate) fn root(&self) -> UpdateKind {
        self.update_kind(ProcessField::Root)
    }

    pub(crate) fn environ(&self) -> UpdateKind {
        self.update_kind(ProcessField::Environ)
    }

    pub(crate) fn cmd(&self) -> UpdateKind {
        self.update_kind(ProcessField::Cmd)
    }

    pub(crate) fn exe(&self) -> UpdateKind {
        self.update_kind(ProcessField::Exe)
    }

    /// Fields requested through [`ProcessRefreshKind`] but unsupported by this platform.
    ///
    /// Adapters must not fabricate values for those fields: they stay untouched (or absent on
    /// freshly discovered processes).
    pub(crate) fn unsupported_fields(&self) -> impl Iterator<Item = ProcessField> + use<> {
        ProcessField::ALL
            .into_iter()
            .filter(move |field| self.fields.fetch(*field) == FieldFetch::Unsupported)
    }

    /// What an adapter must do with a PID once collection is done.
    ///
    /// This centralizes the `updated` flag / `remove_dead_processes` timing so that every
    /// platform performs the exact same commit:
    ///
    /// * `all` + remove dead: every still-tracked process that was not updated is removed.
    /// * `all` + keep: still-tracked processes that were not updated just clear their flag.
    /// * `some` + remove dead: only the *requested* dead PIDs are removed.
    /// * `some` + keep: requested dead PIDs are marked as nonexistent instead of removed.
    ///
    /// PIDs that are not tracked are never added or removed during the commit phase:
    /// discovering a new process belongs to the collection phase.
    pub(crate) fn commit_action(&self, tracked: bool, outcome: Outcome) -> CommitAction {
        match (self.selection, outcome) {
            (_, Outcome::Updated) => CommitAction::KeepAndMarkUpdated,
            // A process that wasn't visited at all.
            (ProcessSelection::All, Outcome::NotUpdated) => {
                if self.dead_processes.remove {
                    CommitAction::Remove
                } else {
                    CommitAction::ClearUpdatedFlag
                }
            }
            // A specifically requested PID that turned out to be dead.
            (ProcessSelection::Some(_), Outcome::NotUpdated) => {
                if self.dead_processes.remove {
                    if tracked {
                        CommitAction::Remove
                    } else {
                        CommitAction::Ignore
                    }
                } else if tracked {
                    CommitAction::MarkNonexistent
                } else {
                    CommitAction::Ignore
                }
            }
        }
    }
}

/// Normalized process selection, preserving the `all`/`some` semantics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProcessSelection {
    /// Every process known to the operating system must be visited.
    All,
    /// Only the listed PIDs must be visited. The slice is kept as provided by the caller: an
    /// empty slice means nothing is visited and duplicates are preserved.
    Some(&'static [Pid]),
}

impl ProcessSelection {
    pub(crate) fn from_request(request: ProcessesToUpdate<'_>) -> Self {
        // The lifetime is erased on purpose: `ProcessRefreshPlan` is a short-lived value that
        // never escapes the refresh call, and the platform only reads it synchronously.
        match request {
            ProcessesToUpdate::All => ProcessSelection::All,
            ProcessesToUpdate::Some(pids) => {
                ProcessSelection::Some(unsafe { extend_slice_lifetime(pids) })
            }
        }
    }

    /// Returns `true` if this PID belongs to the selection.
    pub(crate) fn contains(&self, pid: Pid) -> bool {
        match self {
            ProcessSelection::All => true,
            ProcessSelection::Some(pids) => pids.contains(&pid),
        }
    }

    /// Whether all processes must be visited.
    pub(crate) fn is_all(&self) -> bool {
        matches!(self, ProcessSelection::All)
    }

    /// The explicitly requested PIDs, or an empty slice for `all`.
    pub(crate) fn requested_pids(&self) -> &[Pid] {
        match self {
            ProcessSelection::All => &[],
            ProcessSelection::Some(pids) => pids,
        }
    }

    /// The requested PIDs without duplicates, preserving first-seen order.
    ///
    /// Adapters iterate system listings at most once per PID; duplicate requests are still
    /// counted as duplicate requests via [`ProcessSelection::requested_pids`].
    pub(crate) fn unique_requested_pids(&self) -> Vec<Pid> {
        let mut unique = Vec::new();
        for pid in self.requested_pids() {
            if !unique.contains(pid) {
                unique.push(*pid);
            }
        }
        unique
    }
}

unsafe fn extend_slice_lifetime<'a, T>(slice: &'a [T]) -> &'static [T] {
    unsafe { std::slice::from_raw_parts(slice.as_ptr(), slice.len()) }
}

/// The result of collecting data for one PID.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// Fresh data was collected for the process.
    Updated,
    /// The process could not be updated: either it was not visited (`all`) or it does not
    /// exist (`some`).
    NotUpdated,
}

/// What the commit phase must do with a tracked (or requested) PID.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CommitAction {
    /// Keep the process and mark it as having been updated.
    KeepAndMarkUpdated,
    /// Clear the updated flag without removing the process (`all` + keep dead).
    ClearUpdatedFlag,
    /// Mark the tracked process as nonexistent without removing it (`some` + keep dead).
    MarkNonexistent,
    /// Remove the process from the tracked map.
    Remove,
    /// Do nothing: typically a `some` request for an untracked, dead PID.
    Ignore,
}

/// When and which processes can be removed after collection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DeadProcessPolicy {
    remove: bool,
}

impl DeadProcessPolicy {
    pub(crate) fn new(remove: bool) -> Self {
        Self { remove }
    }

    /// Whether processes found dead among the selected ones must be removed.
    pub(crate) fn removes_dead_processes(&self) -> bool {
        self.remove
    }
}

/// Whether CPU information was requested.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CpuRequested {
    /// CPU usage and accumulated time are part of the refresh.
    Yes,
    /// CPU information must not be computed.
    No,
}

/// Snapshot of the system-wide CPU sampling state when the plan is built.
///
/// It carries no system-specific knowledge: adapters provide the instant of the previous
/// system-wide sample (if any) and their own minimum interval.
#[derive(Clone, Copy, Debug)]
pub(crate) struct CpuSamplingContext {
    /// Instant at which the *system* CPU times were last sampled (global CPU or process CPU),
    /// or `None` if they were never sampled.
    pub(crate) last_system_sample: Option<Instant>,
    /// Platform minimum interval between two CPU samples
    /// ([`crate::MINIMUM_CPU_UPDATE_INTERVAL`]).
    pub(crate) minimum_interval: Duration,
    /// Instant considered as "now" while building the plan.
    pub(crate) now: Instant,
}

impl CpuSamplingContext {
    pub(crate) fn new(
        last_system_sample: Option<Instant>,
        minimum_interval: Duration,
        now: Instant,
    ) -> Self {
        Self { last_system_sample, minimum_interval, now }
    }
}

/// What the platform should do with the system-wide CPU times during this refresh.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SystemCpuAction {
    /// System-wide CPU times must be sampled and the sample timestamp advanced. This is the
    /// first sample: per-process usage cannot be computed yet and remains `0`.
    TakeFirstSample,
    /// System-wide CPU times must be sampled because enough time elapsed; per-process usage can
    /// be computed from deltas.
    TakeSampleAndCompute,
    /// Not enough time elapsed: system-wide times and the timestamp must be left untouched and
    /// previously reported per-process usages must be preserved.
    KeepPreviousSample,
    /// CPU refresh was not requested: nothing CPU related should happen.
    Skip,
}

/// What should happen to a single process' CPU data during this refresh.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProcessCpuAction {
    /// Store raw CPU times but keep usage at `0`. This is the first sample for this process:
    /// a second sample is needed before a usage can be computed.
    RecordFirstSample,
    /// Store raw CPU times and compute usage from the delta.
    RecordSampleAndCompute,
    /// Preserve the previously reported usage and do not rotate raw times.
    KeepPrevious,
    /// CPU refresh was not requested.
    Skip,
}

/// Immutable CPU part of a [`ProcessRefreshPlan`].
#[derive(Clone, Copy, Debug)]
pub(crate) struct CpuPlan {
    requested: bool,
    system_action: SystemCpuAction,
    minimum_interval: Duration,
}

impl CpuPlan {
    fn new(kind: ProcessRefreshKind, sampling: CpuSamplingContext) -> Self {
        let system_action = if !kind.cpu() {
            SystemCpuAction::Skip
        } else {
            match sampling.last_system_sample {
                None => SystemCpuAction::TakeFirstSample,
                Some(last) => {
                    if sampling.now.duration_since(last) >= sampling.minimum_interval {
                        SystemCpuAction::TakeSampleAndCompute
                    } else {
                        SystemCpuAction::KeepPreviousSample
                    }
                }
            }
        };
        Self {
            requested: kind.cpu(),
            system_action,
            minimum_interval: sampling.minimum_interval,
        }
    }

    /// Whether CPU information was requested at all.
    pub(crate) fn requested(&self) -> bool {
        self.requested
    }

    /// What to do with system-wide CPU times.
    pub(crate) fn system_action(&self) -> SystemCpuAction {
        self.system_action
    }

    /// Whether a new system-wide sample should be taken (first sample or enough time elapsed).
    pub(crate) fn take_system_sample(&self) -> bool {
        matches!(
            self.system_action,
            SystemCpuAction::TakeFirstSample | SystemCpuAction::TakeSampleAndCompute
        )
    }

    /// The minimum interval between two CPU samples on this platform.
    pub(crate) fn minimum_interval(&self) -> Duration {
        self.minimum_interval
    }

    /// Per-process decision.
    ///
    /// `has_previous_sample` tells whether this process already has a reference sample:
    /// * no CPU requested → [`ProcessCpuAction::Skip`]
    /// * system keeps its previous sample → [`ProcessCpuAction::KeepPrevious`]
    /// * first system sample → first sample for every process
    /// * later sample and the process has no reference yet → its own first sample
    /// * otherwise → compute the usage from deltas
    pub(crate) fn process_action(&self, has_previous_sample: bool) -> ProcessCpuAction {
        match self.system_action {
            SystemCpuAction::Skip => ProcessCpuAction::Skip,
            SystemCpuAction::KeepPreviousSample => ProcessCpuAction::KeepPrevious,
            SystemCpuAction::TakeFirstSample => ProcessCpuAction::RecordFirstSample,
            SystemCpuAction::TakeSampleAndCompute => {
                if has_previous_sample {
                    ProcessCpuAction::RecordSampleAndCompute
                } else {
                    ProcessCpuAction::RecordFirstSample
                }
            }
        }
    }

    /// Per-process decision for platforms (Windows) which gate each process independently.
    pub(crate) fn process_action_for(
        &self,
        has_previous_sample: bool,
        last_sample: Option<Instant>,
        now: Instant,
    ) -> ProcessCpuAction {
        if !self.requested {
            return ProcessCpuAction::Skip;
        }
        match last_sample {
            None => ProcessCpuAction::RecordFirstSample,
            Some(last) => {
                if now.duration_since(last) >= self.minimum_interval {
                    if has_previous_sample {
                        ProcessCpuAction::RecordSampleAndCompute
                    } else {
                        ProcessCpuAction::RecordFirstSample
                    }
                } else {
                    ProcessCpuAction::KeepPrevious
                }
            }
        }
    }
}
