package org.dependencytrack.model;

public enum WorkflowStep {
    BOM_CONSUMPTION,
    BOM_PROCESSING,
    VULN_ANALYSIS,
    REPO_META_ANALYSIS,
    POLICY_EVALUATION,
    METRICS_UPDATE,
    POLICY_BUNDLE_SYNC
}
