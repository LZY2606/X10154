// Take a look at the license at the top of the repository in the LICENSE file.

//! Platform-independent normalization of process refresh requests.
//!
//! Every platform has to answer the same three questions when
//! [`crate::System::refresh_processes_specifics`] is called:
//!
//! 1. Which processes should be discovered (all of them or an explicit set)?
//! 2. Which fields of each discovered process must be collected?
//! 3. What should happen to the processes that could not be refreshed, and when can
//!    process CPU usage be computed from two samples?
//!
//! Historically, each OS adapter answered these questions on its own, which meant that
//! extending [`ProcessRefreshKind`] or [`ProcessesToUpdate`] required touching every
//! platform. This module turns a refresh request into an immutable
//! [`ProcessRefreshPlan`]. Adapters no longer interpret the public request types: they
//! consume the plan while collecting data and let the common layer
//! ([`ProcessRefreshPlan::commit`]) apply the results.
//!
//! The plan never performs any system call. Capabilities that cannot be provided by a
//! platform are explicitly marked as [`FieldAction::Unsupported`] instead of being
//! silently turned into a successful zero-value refresh.

use crate::{Pid, ProcessRefreshKind, ProcessesToUpdate, UpdateKind};

use std::time::Duration;

/// What an adapter should do with a single process field.
///
/// This action is the only piece of information adapters need when collecting process
/// data. It already accounts for platform capabilities, so an adapter must never turn
/// [`FieldAction::Unsupported`] into a fake successful update.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FieldAction {
    /// The field must not be touched.
    Skip,
    /// The field must be refreshed unconditionally.
    Always,
    /// The field must be refreshed only if it was never collected.
    ///
    /// Whether the field is already set is per-process state, which only the adapter
    /// knows about, so the adapter performs the final check.
    OnlyIfNotSet,
    /// The field was requested but the platform cannot provide it.
    ///
    /// Adapters must leave the stored value untouched (which stays unset/`None`/zero)
    /// instead of reporting a successful refresh.
    Unsupported,
}

impl FieldAction {
    /// Normalizes a user requested [`UpdateKind`] knowing whether the field is
    /// supported by the running platform.
    fn from_update_kind(requested: UpdateKind, supported: bool) -> Self {
        if !supported {
            return Self::Unsupported;
        }
        match requested {
            UpdateKind::Never => Self::Skip,
            UpdateKind::Always => Self::Always,
            UpdateKind::OnlyIfNotSet => Self::OnlyIfNotSet,
        }
   

    /// Normalizes a boolean refresh flag knowing whether the field is supported by the
    /// running platform.
    fn from_flag(requested: bool, supported: bool) -> Self {
        if !supported {
            return Self::Unsupported;
        }
        if requested {
            Self::Always
        } else {
            Self::Skip
        }
    }

    /// Returns `true` if the field must be collected without any precondition.
    pub(crate) fn is_always(self) -> bool {
        self == Self::Always
    }

    /// Returns `true` if the field was requested but cannot be provided.
    pub(crate) fn is_unsupported(self) -> bool {
        self == Self::Unsupported
    }

    /// Returns `true` if some collection is expected.
    ///
    /// For [`FieldAction::OnlyIfNotSet`], the `already_set` closure receives the
    /// per-process state only the adapter has access to.
    pub(crate) fn needs_update(self, already_set: impl FnOnce() -> bool) -> bool {
        match self {
            Self::Skip | Self::Unsupported => false,
            Self::Always => true,
            Self::OnlyIfNotSet => !already_set(),
        }
    }
}

/// Collection instructions for every refreshable process field.
///
/// Each field is independent and already takes platform capabilities into account.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProcessFieldsPlan {
    pub(crate) cpu: FieldAction,
    pub(crate) disk_usage: FieldAction,
    pub(crate) memory: FieldAction,
    pub(crate) user: FieldAction,
    pub(crate) cwd: FieldAction,
    pub(crate) root: FieldAction,
    pub(crate) environ: FieldAction,
    pub(crate) cmd: FieldAction,
    pub(crate) exe: FieldAction,
    pub(crate) tasks: FieldAction,
    pub(crate) gpu_usage: FieldAction,
    pub(crate) gpu_memory: FieldAction,
}

impl ProcessFieldsPlan {
    fn new(kind: ProcessRefreshKind, caps: &ProcessCapabilities) -> Self {
        Self {
            cpu: FieldAction::from_flag(kind.cpu(), caps.cpu),
            disk_usage: FieldAction::from_flag(kind.disk_usage(), caps.disk_usage),
            memory: FieldAction::from_flag(kind.memory(), caps.memory),
            user: FieldAction::from_update_kind(kind.user(), caps.user),
            cwd: FieldAction::from_update_kind(kind.cwd(), caps.cwd),
            root: FieldAction::from_update_kind(kind.root(), caps.root),
            environ: FieldAction::from_update_kind(kind.environ(), caps.environ),
            cmd: FieldAction::from_update_kind(kind.cmd(), caps.cmd),
            exe: FieldAction::from_update_kind(kind.exe(), caps.exe),
            tasks: FieldAction::from_flag(kind.tasks(), caps.tasks),
            gpu_usage: FieldAction::from_flag(
                kind.gpu_usage(),
                caps.gpu_usage && cfg!(feature = "gpu"),
            ),
            gpu_memory: FieldAction::from_flag(
                kind.gpu_memory(),
                caps.gpu_memory && cfg!(feature = "gpu"),
            ),
        }
    }

    /// Returns `true` if CPU counters have to be read while collecting a process.
    ///
    /// Raw CPU times are always read when the field is supported because the adapter
    /// needs two samples before it can compute a usage percentage.
    pub(crate) fn cpu_requested(&self) -> bool {
        !matches!(self.cpu, FieldAction::Skip | FieldAction::Unsupported)
    }
}

/// Whether the CPU clock samples required to compute a process usage percentage are
/// available right now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CpuSamplingState {
    /// No sample has ever been taken: the adapter stores the counters but leaves the
    /// usage percentage untouched.
    FirstSample,
    /// Less than the platform minimum interval elapsed since the previous sample:
    /// the adapter stores the counters but leaves the usage percentage untouched.
    IntervalNotElapsed,
    /// Two samples separated by at least the minimum interval are available: the
    /// adapter computes the usage percentage from them.
    IntervalElapsed,
}

/// Whether the plan can decide CPU sampling state centrally or whether each process
/// must do it itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CpuClockGating {
    /// A single clock is shared by all processes (Linux global `/proc/stat` and macOS
    /// host info). The state is computed once, while building the plan.
    Global { state: CpuSamplingState },
    /// Every process owns its own sampling clock (Windows `GetProcessTimes`). The
    /// adapter applies the minimum interval per process.
    PerProcess,
    /// The platform returns CPU usage directly from the kernel (FreeBSD/NetBSD
    /// `ki_pctcpu`), so there is no sampling clock involved.
    NotNeeded,
    /// Process CPU information is not available at all (unsupported targets).
    Unsupported,
}

/// CPU collection instructions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CpuPlan {
    /// What to do with the CPU field itself.
    pub(crate) field: FieldAction,
    /// How the minimum interval between two usage samples is enforced.
    pub(crate) gating: CpuClockGating,
    /// Minimum time between two samples used to compute a usage percentage.
    pub(crate) minimum_interval: Duration,
}

impl CpuPlan {
    /// Returns the sampling state known at plan build time, if any.
    pub(crate) fn global_state(&self) -> Option<CpuSamplingState> {
        match self.gating {
            CpuClockGating::Global { state } => Some(state),
            _ => None,
        }
    }
}

/// Normalized process selection.
///
/// Duplicated PIDs are collapsed so each process is collected exactly once. The
/// original ordering is preserved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProcessSelection<'a> {
    /// Enumerate every process (and, on supporting platforms, tasks) known to the OS.
    All,
    /// Enumerate only the given PIDs. The slice never contains duplicates and may be
    /// empty: adapters must skip enumeration entirely in that case.
    Some(&'a [Pid]),
}

/// Whether processes that could not be refreshed must be removed or kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RemoveDeadPolicy {
    /// Dead/non-existent refreshed processes are removed from the process list.
    Remove,
    /// Dead/non-existent refreshed processes are kept and marked as non-existent.
    KeepAndMark,
}

/// Static description of what a platform can collect.
///
/// Each OS adapter exposes one `const` value of this type. The compile-time guard in
/// [`ProcessRefreshPlan`] forces new platforms to provide the mapping instead of
/// silently inheriting another platform's semantics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProcessCapabilities {
    pub(crate) cpu: bool,
    pub(crate) disk_usage: bool,
    pub(crate) memory: bool,
    pub(crate) user: bool,
    pub(crate) cwd: bool,
    pub(crate) root: bool,
    pub(crate) environ: bool,
    pub(crate) cmd: bool,
    pub(crate) exe: bool,
    pub(crate) tasks: bool,
    pub(crate) gpu_usage: bool,
    pub(crate) gpu_memory: bool,
    /// How CPU usage sampling is gated by the platform.
    pub(crate) cpu_gating: CpuClockGating,
    /// Minimum interval required between two CPU usage samples.
    pub(crate) minimum_cpu_interval: Duration,
}

impl ProcessCapabilities {
    /// Capabilities of a platform on which no process information can be collected.
    pub(crate) const UNSUPPORTED: Self = Self {
        cpu: false,
        disk_usage: false,
        memory: false,
        user: false,
        cwd: false,
        root: false,
        environ: false,
        cmd: false,
        exe: false,
        tasks: false,
        gpu_usage: false,
        gpu_memory: false,
        cpu_gating: CpuClockGating::Unsupported,
        minimum_cpu_interval: Duration::ZERO,
    };
}

/// Immutable, platform-independent execution plan for one process refresh call.
///
/// Built by [`ProcessRefreshPlan::new`] from the public request types and consumed by
/// the OS adapter while collecting data. Adapters must not inspect the original
/// request types: all semantics live here.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ProcessRefreshPlan<'a> {
    selection: ProcessSelection<'a>,
    fields: ProcessFieldsPlan,
    cpu: CpuPlan,
    remove_dead: RemoveDeadPolicy,
}

impl<'a> ProcessRefreshPlan<'a> {
    /// Normalizes a refresh request into an execution plan.
    ///
    /// * `kind` is the requested set of fields.
    /// * `processes` selects which processes must be enumerated.
    /// * `remove_dead_processes` selects what happens to refreshed PIDs that do not
    ///   exist anymore.
    /// * `caps` describes what the running platform can collect.
    /// * `now`/`last_cpu_sample` describe the shared CPU clock for platforms relying on
    ///   [`CpuClockGating::Global`]. They are ignored by the other gating modes.
    ///
    /// Duplicated PIDs in a [`ProcessesToUpdate::Some`] request are collapsed while
    /// preserving the first occurrence order.
    pub(crate) fn build(
        kind: ProcessRefreshKind,
        processes: ProcessesToUpdate<'a>,
        remove_dead_processes: bool,
        caps: &ProcessCapabilities,
        now: std::time::Instant,
        last_cpu_sample: Option<std::time::Instant>,
    ) -> Self {
        let selection = match processes {
            ProcessesToUpdate::All => ProcessSelection::All,
            ProcessesToUpdate::Some(pids) => {
                ProcessSelection::Some(normalize_pids(pids, scratch))
            }
        };

        let fields = ProcessFieldsPlan::new(kind, caps);

        let gating = match caps.cpu_gating {
            CpuClockGating::Global { .. } => {
                let state = match last_cpu_sample {
                    None => CpuSamplingState::FirstSample,
                    Some(last) => {
                        if now.duration_since(last) >= caps.minimum_cpu_interval {
                            CpuSamplingState::IntervalElapsed
                        } else {
                            CpuSamplingState::IntervalNotElapsed
                        }
                    }
                };
                CpuClockGating::Global { state }
            }
            other => other,
        };
        let cpu = CpuPlan {
            field: fields.cpu,
            gating,
            minimum_interval: caps.minimum_cpu_interval,
        };

        let remove_dead = if remove_dead_processes {
            RemoveDeadPolicy::Remove
        } else {
            RemoveDeadPolicy::KeepAndMark
        };

        Self {
            selection,
            fields,
            cpu,
            remove_dead,
        }
    }

    /// Which processes the adapter must enumerate.
    pub(crate) fn selection(&self) -> ProcessSelection<'_> {
        self.selection
    }

    /// Field collection instructions.
    pub(crate) fn fields(&self) -> &ProcessFieldsPlan {
        &self.fields
    }

    /// CPU collection instructions.
    pub(crate) fn cpu(&self) -> &CpuPlan {
        &self.cpu
    }

    /// Whether dead refreshed processes must be removed or kept and marked.
    pub(crate) fn remove_dead(&self) -> RemoveDeadPolicy {
        self.remove_dead
    }

    /// Returns `true` if no process must be enumerated.
    pub(crate) fn is_empty_selection(&self) -> bool {
        matches!(self.selection, ProcessSelection::Some(pids) if pids.is_empty())
    }

    /// Iterates over the PIDs explicitly selected by the plan.
    pub(crate) fn selected_pids(&self) -> &[Pid] {
        match self.selection {
            ProcessSelection::Some(pids) => pids,
            ProcessSelection::All => &[],
        }
    }
}

fn normalize_pids<'a>(pids: &'a [Pid], scratch: &'a mut Vec<Pid>) -> &'a [Pid] {
    // Fast path: no duplicate, borrow the caller slice directly without touching
    // `scratch`. Explicit refresh sets are small, so the quadratic scan is cheap.
    let mut has_duplicate = false;
    for (i, pid) in pids.iter().enumerate() {
        if pids[..i].iter().any(|other| other == pid) {
            has_duplicate = true;
            break;
        }
    }
    if !has_duplicate {
        return pids;
    }
    scratch.clear();
    for pid in pids {
        if !scratch.contains(pid) {
            scratch.push(*pid);
        }
    }
    scratch.as_slice()
}
