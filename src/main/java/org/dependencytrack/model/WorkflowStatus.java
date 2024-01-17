package org.dependencytrack.model;

public enum WorkflowStatus {

    PENDING(false),
    TIMED_OUT(false),
    COMPLETED(true),
    FAILED(true),
    CANCELLED(true),
    NOT_APPLICABLE(true);

    private final boolean terminal;

    WorkflowStatus(final boolean terminal) {
        this.terminal = terminal;
    }

    public boolean isTerminal() {
        return terminal;
    }

}
