package org.dependencytrack.model;

public enum FetchStatus {
    //request processed successfully
    PROCESSED,
    //fetching information for this component is in progress
    IN_PROGRESS,

    //to be used when information is not available in source of truth so we don't go fetching this repo information again
    //after first attempt
    NOT_AVAILABLE
}
