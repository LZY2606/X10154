// Take a look at the license at the top of the repository in the LICENSE file.

// On the `unknown` backend, the adapter-facing part of the plan is unused
// because the backend cannot collect anything.
#![cfg_attr(feature = "unknown-ci", allow(dead_code))]

//! Platform-independent normalization of process refresh requests.
//!
//! A [`ProcessRefreshPlan`] is built from the public refresh arguments (a
//! [`ProcessRefreshKind`], a [`ProcessesToUpdate`] selection and the
//! `remove_dead_processes` flag) combined with the [`PlatformCapabilities`]
//! of the backend of the current platform.
//!
//! The plan is immutable once built. Platform adapters never re-interpret the
//! request: they only collect data for the processes selected by the plan,
//! using the (capability-filtered) refresh kind of the plan, and the common
//! layer commits the result according to the plan.
//!
//! Fields requested but not supported by a platform are masked out of the
//! effective refresh kind and reported through [`UnsupportedFields`]; they are
//! never silently faked as successful zero values.

use crate::{Pid, ProcessRefreshKind, ProcessesToUpdate, UpdateKind};

use std::collections::HashSet;
use std::time::{Duration, Instant};

/// What a platform backend can provide when refreshing processes.
///
/// Every backend exposes exactly one of these through
/// `crate::sys::process_refresh_capabilities`. The common layer relies on
/// this function unconditionally, so a new platform that does not provide the
/// mapping fails to compile.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PlatformCapabilities {
    /// Fields the backend is able to collect.
    supported_fields: ProcessRefreshKind,
    /// Minimum time between two CPU usage computations.
    min_cpu_update_interval: Duration,
    /// Whether the backend can enumerate and add processes to the process
    /// list (`false` on backends where process listing is unavailable).
    can_list_processes: bool,
}

impl PlatformCapabilities {
    /// Builds the capability mapping of a platform.
    pub(crate) const fn new(
        supported_fields: ProcessRefreshKind,
        min_cpu_update_interval: Duration,
        can_list_processes: bool,
    ) -> Self {
        Self {
            supported_fields,
            min_cpu_update_interval,
            can_list_processes,
        }
    }

    /// Fields the backend is able to collect.
    pub(crate) fn supported_fields(&self) -> ProcessRefreshKind {
        self.supported_fields
    }

    /// Minimum time between two CPU usage computations.
    #[allow(dead_code)] // Used by tests and some platform adapters only.
    pub(crate) fn min_cpu_update_interval(&self) -> Duration {
        self.min_cpu_update_interval
    }

    /// Whether the backend can enumerate and add processes.
    #[allow(dead_code)] // Used by tests and some platform adapters only.
    pub(crate) fn can_list_processes(&self) -> bool {
        self.can_list_processes
    }
}

/// Normalized, immutable process selection.
///
/// Duplicated PIDs in a [`ProcessesToUpdate::Some`] request are merged: only
/// the first occurrence is kept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PlanSelection {
    /// Enumerate every process on the system, discovering new ones.
    All,
    /// Refresh only the listed processes.
    ///
    /// Unknown PIDs are simply absent from the collect phase: they are neither
    /// discovered nor treated as errors. PIDs not tracked yet are still
    /// discovered if they exist on the system.
    Some(Vec<Pid>),
}

/// Fields which were requested through [`ProcessRefreshKind`] but cannot be
/// collected by the current backend.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct UnsupportedFields {
    /// `cpu` requested but unsupported.
    pub(crate) cpu: bool,
    /// `disk_usage` requested but unsupported.
    pub(crate) disk_usage: bool,
    /// `memory` requested but unsupported.
    pub(crate) memory: bool,
    /// `user` requested but unsupported.
    pub(crate) user: bool,
    /// `cwd` requested but unsupported.
    pub(crate) cwd: bool,
    /// `root` requested but unsupported.
    pub(crate) root: bool,
    /// `environ` requested but unsupported.
    pub(crate) environ: bool,
    /// `cmd` requested but unsupported.
    pub(crate) cmd: bool,
    /// `exe` requested but unsupported.
    pub(crate) exe: bool,
    /// `tasks` requested but unsupported.
    pub(crate) tasks: bool,
    /// `gpu_usage` requested but unsupported.
    pub(crate) gpu_usage: bool,
    /// `gpu_memory` requested but unsupported.
    pub(crate) gpu_memory: bool,
}

impl UnsupportedFields {
    /// Returns `true` if at least one requested field is unsupported.
    #[allow(dead_code)] // Used by tests and some platform adapters only.
    pub(crate) fn any(&self) -> bool {
        *self != Self::default()
    }
}

/// What the collect phase must do with CPU usage for this refresh.
#[allow(dead_code)] // Used by tests and some platform adapters only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CpuUpdate {
    /// CPU information was not requested or is unsupported: nothing to do.
    NotRequested,
    /// No previous sample exists.
    ///
    /// The backend collects raw counters but the reported usage remains `0.0`:
    /// a usage value needs two samples.
    FirstSample,
    /// Enough time elapsed since the previous sample: compute the diff and
    /// report the new usage.
    Diff,
    /// The refresh happened too close to the previous sample: collect nothing
    /// and keep the previously reported value.
    Deferred,
}

/// Immutable, platform-independent execution plan for a process refresh.
#[derive(Clone, Debug)]
pub(crate) struct ProcessRefreshPlan {
    selection: PlanSelection,
    /// Requested kind after masking out fields unsupported by the backend.
    refresh_kind: ProcessRefreshKind,
    /// Requested fields which the backend cannot provide.
    unsupported_fields: UnsupportedFields,
    min_cpu_update_interval: Duration,
    can_list_processes: bool,
    remove_dead_processes: bool,
}

impl ProcessRefreshPlan {
    /// Normalizes a refresh request into an immutable plan.
    pub(crate) fn new(
        processes_to_update: ProcessesToUpdate<'_>,
        refresh_kind: ProcessRefreshKind,
        remove_dead_processes: bool,
        capabilities: &PlatformCapabilities,
    ) -> Self {
        let selection = match processes_to_update {
            ProcessesToUpdate::All => PlanSelection::All,
            ProcessesToUpdate::Some(pids) => {
                let mut seen = HashSet::with_capacity(pids.len());
                PlanSelection::Some(
                    pids.iter()
                        .copied()
                        .filter(|pid| seen.insert(*pid))
                        .collect(),
                )
            }
        };
        let (refresh_kind, unsupported_fields) = mask_refresh_kind(refresh_kind, capabilities);
        Self {
            selection,
            refresh_kind,
            unsupported_fields,
            min_cpu_update_interval: capabilities.min_cpu_update_interval,
            can_list_processes: capabilities.can_list_processes,
            remove_dead_processes,
        }
    }

    /// Whether the collect phase has anything to run.
    ///
    /// It is `false` when the backend cannot list processes or when the
    /// normalized [`ProcessesToUpdate::Some`] selection is empty.
    pub(crate) fn should_collect(&self) -> bool {
        self.can_list_processes
            && !matches!(&self.selection, PlanSelection::Some(pids) if pids.is_empty())
    }

    /// Normalized process selection.
    pub(crate) fn selection(&self) -> &PlanSelection {
        &self.selection
    }

    /// Returns `true` if `pid` belongs to the normalized selection.
    pub(crate) fn includes_pid(&self, pid: Pid) -> bool {
        match &self.selection {
            PlanSelection::All => true,
            PlanSelection::Some(pids) => pids.contains(&pid),
        }
    }

    /// Reconstructs a [`ProcessesToUpdate`] view for the adapter's collect
    /// phase. PIDs are already deduplicated.
    #[allow(dead_code)] // Used by some platform adapters only.
    pub(crate) fn processes_to_update(&self) -> ProcessesToUpdate<'_> {
        match &self.selection {
            PlanSelection::All => ProcessesToUpdate::All,
            PlanSelection::Some(pids) => ProcessesToUpdate::Some(pids),
        }
    }

    /// Refresh kind with unsupported fields masked out. This is the only kind
    /// adapters are allowed to use while collecting.
    pub(crate) fn refresh_kind(&self) -> ProcessRefreshKind {
        self.refresh_kind
    }

    /// Requested fields that the backend does not support.
    #[allow(dead_code)] // Used by tests and some platform adapters only.
    pub(crate) fn unsupported_fields(&self) -> UnsupportedFields {
        self.unsupported_fields
    }

    /// Whether dead processes must be removed during the commit phase.
    pub(crate) fn remove_dead_processes(&self) -> bool {
        self.remove_dead_processes
    }

    /// Minimum interval between two CPU usage computations for this backend.
    #[allow(dead_code)] // Used by tests and some platform adapters only.
    pub(crate) fn min_cpu_update_interval(&self) -> Duration {
        self.min_cpu_update_interval
    }

    /// Pure CPU update decision derived from the previous sampling state.
    ///
    /// * CPU not requested (or masked as unsupported): [`CpuUpdate::NotRequested`]
    /// * no previous sample: [`CpuUpdate::FirstSample`] (report `0.0`)
    /// * elapsed time below [`ProcessRefreshPlan::min_cpu_update_interval`]:
    ///   [`CpuUpdate::Deferred`] (keep the previous value)
    /// * otherwise: [`CpuUpdate::Diff`]
    #[allow(dead_code)] // Used by tests and some platform adapters only.
    pub(crate) fn cpu_update(&self, last_sample: Option<Instant>, now: Instant) -> CpuUpdate {
        if !self.refresh_kind.cpu() {
            return CpuUpdate::NotRequested;
        }
        match last_sample {
            None => CpuUpdate::FirstSample,
            Some(last) => {
                if now.duration_since(last) >= self.min_cpu_update_interval {
                    CpuUpdate::Diff
                } else {
                    CpuUpdate::Deferred
                }
            }
        }
    }
}

fn mask_refresh_kind(
    kind: ProcessRefreshKind,
    capabilities: &PlatformCapabilities,
) -> (ProcessRefreshKind, UnsupportedFields) {
    let supported = capabilities.supported_fields();
    let mut effective = kind;
    let mut unsupported = UnsupportedFields::default();

    macro_rules! mask_boolean_field {
        ($field:ident, $without:ident) => {
            if effective.$field() && !supported.$field() {
                effective = effective.$without();
                unsupported.$field = true;
            }
        };
    }
    mask_boolean_field!(cpu, without_cpu);
    mask_boolean_field!(disk_usage, without_disk_usage);
    mask_boolean_field!(memory, without_memory);
    mask_boolean_field!(tasks, without_tasks);
    mask_boolean_field!(gpu_usage, without_gpu_usage);
    mask_boolean_field!(gpu_memory, without_gpu_memory);

    macro_rules! mask_update_kind_field {
        ($field:ident, $without:ident) => {
            if effective.$field() != UpdateKind::Never
                && supported.$field() == UpdateKind::Never
            {
                effective = effective.$without();
                unsupported.$field = true;
            }
        };
    }
    mask_update_kind_field!(user, without_user);
    mask_update_kind_field!(cwd, without_cwd);
    mask_update_kind_field!(root, without_root);
    mask_update_kind_field!(environ, without_environ);
    mask_update_kind_field!(cmd, without_cmd);
    mask_update_kind_field!(exe, without_exe);

    (effective, unsupported)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    const MIN_INTERVAL: Duration = Duration::from_millis(200);

    fn full_capabilities() -> PlatformCapabilities {
        PlatformCapabilities::new(ProcessRefreshKind::everything(), MIN_INTERVAL, true)
    }

    /// Only `cpu` and `memory` can be collected.
    fn limited_capabilities() -> PlatformCapabilities {
        let supported = ProcessRefreshKind::nothing()
            .without_tasks()
            .with_cpu()
            .with_memory();
        PlatformCapabilities::new(supported, MIN_INTERVAL, true)
    }

    fn no_listing_capabilities() -> PlatformCapabilities {
        PlatformCapabilities::new(
            ProcessRefreshKind::nothing().without_tasks(),
            MIN_INTERVAL,
            false,
        )
    }

    fn plan_for(
        selection: ProcessesToUpdate<'_>,
        kind: ProcessRefreshKind,
        caps: &PlatformCapabilities,
    ) -> ProcessRefreshPlan {
        ProcessRefreshPlan::new(selection, kind, true, caps)
    }

    #[test]
    fn first_cpu_sample_is_first_sample() {
        let plan = plan_for(
            ProcessesToUpdate::All,
            ProcessRefreshKind::everything(),
            &full_capabilities(),
        );
        assert_eq!(
            plan.cpu_update(None, Instant::now()),
            CpuUpdate::FirstSample
        );
    }

    #[test]
    fn cpu_sample_after_interval_is_a_diff() {
        let plan = plan_for(
            ProcessesToUpdate::All,
            ProcessRefreshKind::nothing().with_cpu(),
            &full_capabilities(),
        );
        let now = Instant::now();
        assert_eq!(
            plan.cpu_update(Some(now - MIN_INTERVAL), now),
            CpuUpdate::Diff
        );
        assert_eq!(plan.cpu_update(Some(now), now), CpuUpdate::Diff);
    }

    #[test]
    fn cpu_sample_too_soon_is_deferred() {
        let plan = plan_for(
            ProcessesToUpdate::All,
            ProcessRefreshKind::nothing().with_cpu(),
            &full_capabilities(),
        );
        let now = Instant::now();
        let last = now - MIN_INTERVAL + Duration::from_millis(1);
        assert_eq!(plan.cpu_update(Some(last), now), CpuUpdate::Deferred);
    }

    #[test]
    fn cpu_not_requested_is_not_requested() {
        let plan = plan_for(
            ProcessesToUpdate::All,
            ProcessRefreshKind::nothing(),
            &full_capabilities(),
        );
        assert_eq!(
            plan.cpu_update(None, Instant::now()),
            CpuUpdate::NotRequested
        );
    }

    #[test]
    fn cpu_unsupported_is_masked_not_faked() {
        let caps = PlatformCapabilities::new(
            ProcessRefreshKind::nothing().without_tasks().with_memory(),
            MIN_INTERVAL,
            true,
        );
        let plan = plan_for(
            ProcessesToUpdate::All,
            ProcessRefreshKind::everything(),
            &caps,
        );
        assert_eq!(
            plan.cpu_update(None, Instant::now()),
            CpuUpdate::NotRequested
        );
        assert!(!plan.refresh_kind().cpu());
        assert!(plan.unsupported_fields().cpu);
        assert!(plan.refresh_kind().memory());
        assert!(!plan.unsupported_fields().memory);
    }

    #[test]
    fn empty_pid_set_is_not_collected() {
        let plan = plan_for(
            ProcessesToUpdate::Some(&[]),
            ProcessRefreshKind::everything(),
            &full_capabilities(),
        );
        assert!(!plan.should_collect());
        assert_eq!(plan.selection(), &PlanSelection::Some(Vec::new()));
    }

    #[test]
    fn duplicate_pids_are_deduplicated_first_occurrence_kept() {
        let pids = [
            Pid::from(3usize),
            Pid::from(1usize),
            Pid::from(3usize),
            Pid::from(2usize),
            Pid::from(1usize),
        ];
        let plan = plan_for(
            ProcessesToUpdate::Some(&pids),
            ProcessRefreshKind::nothing(),
            &full_capabilities(),
        );
        assert_eq!(
            plan.selection(),
            &PlanSelection::Some(vec![
                Pid::from(3usize),
                Pid::from(1usize),
                Pid::from(2usize)
            ])
        );
    }

    #[test]
    fn all_selection_discovers_new_processes() {
        let plan = plan_for(
            ProcessesToUpdate::All,
            ProcessRefreshKind::nothing(),
            &full_capabilities(),
        );
        assert_eq!(plan.selection(), &PlanSelection::All);
        assert!(plan.should_collect());
        assert!(plan.includes_pid(Pid::from(12_345usize)));
        assert_eq!(plan.processes_to_update(), ProcessesToUpdate::All);
    }

    #[test]
    fn some_selection_updates_only_listed_pids() {
        let listed = [Pid::from(42usize)];
        let plan = plan_for(
            ProcessesToUpdate::Some(&listed),
            ProcessRefreshKind::nothing(),
            &full_capabilities(),
        );
        assert!(plan.should_collect());
        assert!(plan.includes_pid(Pid::from(42usize)));
        assert!(!plan.includes_pid(Pid::from(43usize)));
        assert_eq!(
            plan.processes_to_update(),
            ProcessesToUpdate::Some(&[Pid::from(42usize)])
        );
    }

    #[test]
    fn unknown_pids_are_kept_in_selection() {
        // A pid which does not exist on the system stays in the plan: the
        // collect phase simply finds nothing for it.
        let plan = plan_for(
            ProcessesToUpdate::Some(&[Pid::from(usize::MAX)]),
            ProcessRefreshKind::nothing(),
            &full_capabilities(),
        );
        assert!(plan.should_collect());
        assert!(plan.includes_pid(Pid::from(usize::MAX)));
    }

    #[test]
    fn partial_fields_are_masked_and_reported() {
        let plan = plan_for(
            ProcessesToUpdate::All,
            ProcessRefreshKind::everything(),
            &limited_capabilities(),
        );
        let kind = plan.refresh_kind();
        assert!(kind.cpu());
        assert!(kind.memory());
        assert!(!kind.disk_usage());
        assert!(!kind.tasks());
        assert_eq!(kind.exe(), UpdateKind::Never);
        assert_eq!(kind.environ(), UpdateKind::Never);
        let unsupported = plan.unsupported_fields();
        assert!(unsupported.any());
        assert!(unsupported.disk_usage);
        assert!(unsupported.tasks);
        assert!(unsupported.exe);
        assert!(unsupported.environ);
        assert!(!unsupported.cpu);
        assert!(!unsupported.memory);
    }

    #[test]
    fn platform_without_listing_never_collects() {
        let plan = plan_for(
            ProcessesToUpdate::All,
            ProcessRefreshKind::everything(),
            &no_listing_capabilities(),
        );
        assert!(!plan.should_collect());
        // All fields are reported as unsupported, none is faked.
        let unsupported = plan.unsupported_fields();
        assert!(unsupported.cpu);
        assert!(unsupported.memory);
        assert!(unsupported.cmd);
    }

    #[test]
    fn remove_dead_processes_flag_is_preserved() {
        let caps = full_capabilities();
        let with_removal = ProcessRefreshPlan::new(
            ProcessesToUpdate::All,
            ProcessRefreshKind::nothing(),
            true,
            &caps,
        );
        let without_removal = ProcessRefreshPlan::new(
            ProcessesToUpdate::All,
            ProcessRefreshKind::nothing(),
            false,
            &caps,
        );
        assert!(with_removal.remove_dead_processes());
        assert!(!without_removal.remove_dead_processes());
    }

    #[test]
    fn min_interval_comes_from_capabilities() {
        let plan = plan_for(
            ProcessesToUpdate::All,
            ProcessRefreshKind::nothing(),
            &full_capabilities(),
        );
        assert_eq!(plan.min_cpu_update_interval(), MIN_INTERVAL);
    }

    #[test]
    fn platform_capabilities_mapping_exists_and_is_consistent() {
        // Test-time guard: every platform must provide its capability mapping
        // (the common layer also fails to compile without it).
        let caps = crate::sys::process_refresh_capabilities();
        assert_eq!(
            caps.min_cpu_update_interval(),
            crate::MINIMUM_CPU_UPDATE_INTERVAL,
            "capabilities must expose the platform minimum CPU update interval",
        );
        if !caps.can_list_processes() {
            // A backend which cannot list processes must not claim to support
            // any field: nothing would be collected anyway.
            let supported = caps.supported_fields();
            assert!(!supported.cpu());
            assert!(!supported.memory());
            assert!(!supported.disk_usage());
            assert!(!supported.tasks());
            assert_eq!(supported.exe(), UpdateKind::Never);
            assert_eq!(supported.cmd(), UpdateKind::Never);
        }
    }

    /// Shared contract exercised by every platform adapter: each adapter
    /// consumes the same plan and keeps the historical commit-phase behavior
    /// (dead process removal and CPU diffing).
    pub(crate) fn platform_adapter_contract() {
        use crate::{ProcessRefreshKind, System};

        let caps = crate::sys::process_refresh_capabilities();
        assert_eq!(
            caps.min_cpu_update_interval(),
            crate::MINIMUM_CPU_UPDATE_INTERVAL,
        );

        if !caps.can_list_processes() {
            // The refresh must be a no-op, not a fake success.
            if let Ok(mut s) = System::new() {
                assert_eq!(s.refresh_processes(ProcessesToUpdate::All, true), 0);
                assert!(s.processes().is_empty());
            }
            return;
        }

        let Ok(mut s) = System::new() else {
            return;
        };
        let Ok(pid) = crate::get_current_pid() else {
            return;
        };

        // `Some` selection: the current process is discovered even though the
        // process list starts empty.
        let nb_updated = s.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[pid]),
            true,
            ProcessRefreshKind::everything(),
        );
        assert!(nb_updated > 0, "the current process should be refreshed");
        assert!(s.process(pid).is_some());

        // CPU contract: a first sample establishes the baseline, a later
        // refresh past the minimum interval computes a diff.
        std::thread::sleep(crate::MINIMUM_CPU_UPDATE_INTERVAL);
        s.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[pid]),
            true,
            ProcessRefreshKind::nothing().with_cpu(),
        );
        let usage = s.process(pid).map(|p| p.cpu_usage());
        assert!(
            usage.is_some_and(|u| u.is_finite() && u >= 0.),
            "CPU usage must stay a finite, non-negative value, got {usage:?}",
        );

        // Commit phase: refreshing `All` with removal of dead processes keeps
        // alive processes in the list.
        s.refresh_processes(ProcessesToUpdate::All, true);
        assert!(s.process(pid).is_some());

        // Unknown pids are ignored by the collect phase: they are neither
        // discovered nor errors.
        let unknown = Pid::from(usize::MAX);
        s.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[unknown]),
            true,
            ProcessRefreshKind::everything(),
        );
        assert!(s.process(unknown).is_none());
    }
}
