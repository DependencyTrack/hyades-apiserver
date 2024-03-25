package org.dependencytrack.model;

public enum FetchStatus {
    //request processed successfully
    PROCESSED,
    //fetching information for this component is in progress
    IN_PROGRESS,
    NOT_AVAILABLE
}
