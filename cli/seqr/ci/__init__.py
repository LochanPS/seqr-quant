"""CI gate: diff-aware, policy-aware PQC scanning that blocks drift on pull requests.

The regression-guard arm of the SeQr lifecycle (docs/07_GitHub_App_PRD.md,
docs/13_Platform_Spine_PRD.md): scan the crypto a change introduces, evaluate it against
the org's declared crypto policy, subtract accepted findings (baseline + suppressions),
render a PR-style review, and optionally fail the build — on severity (--fail-on/--policy)
or on NEW drift from policy (--fail-on-drift). Exit 0 by default.
"""
from seqr.ci.baseline import (
    Baseline,
    build_baseline,
    fingerprint,
    filter_new,
    find_baseline_file,
    load_baseline,
    save_baseline,
)
from seqr.ci.config import CIConfigError, find_config_file, load_config
from seqr.ci.diff import GitDiffError, auto_base, git_diff, parse_unified_diff
from seqr.ci.gate import GateDecision, decide, filter_to_added, normalize_path
from seqr.ci.policy import (
    CryptoPolicy,
    PolicyViolation,
    evaluate_findings,
    find_policy_file,
    load_policy,
)
from seqr.ci.report import build_markdown
from seqr.ci.suppress import (
    Suppressed,
    apply_inline_suppressions,
    apply_path_ignores,
    load_seqrignore,
)
from seqr.ci.trend import (
    DEFAULT_SNAPSHOT_DIR,
    BudgetDecision,
    TrendDiff,
    budget_decision,
    build_snapshot,
    build_trend_json,
    build_trend_markdown,
    diff_snapshots,
    git_commit,
    load_snapshots,
    prior_snapshot,
    save_snapshot,
)

__all__ = [
    # diff
    "parse_unified_diff",
    "git_diff",
    "auto_base",
    "GitDiffError",
    # gate
    "filter_to_added",
    "normalize_path",
    "decide",
    "GateDecision",
    # policy
    "CryptoPolicy",
    "PolicyViolation",
    "load_policy",
    "find_policy_file",
    "evaluate_findings",
    # baseline
    "Baseline",
    "fingerprint",
    "load_baseline",
    "save_baseline",
    "build_baseline",
    "filter_new",
    "find_baseline_file",
    # suppressions
    "Suppressed",
    "apply_inline_suppressions",
    "apply_path_ignores",
    "load_seqrignore",
    # config
    "load_config",
    "find_config_file",
    "CIConfigError",
    # report
    "build_markdown",
    # trend (scheduled, whole-tree drift over time + fail-budget)
    "DEFAULT_SNAPSHOT_DIR",
    "git_commit",
    "build_snapshot",
    "save_snapshot",
    "load_snapshots",
    "prior_snapshot",
    "TrendDiff",
    "diff_snapshots",
    "BudgetDecision",
    "budget_decision",
    "build_trend_markdown",
    "build_trend_json",
]
