package org.dependencytrack.model;

public enum IntegrityMatchStatus {
    HASH_MATCH_PASSED,
    HASH_MATCH_FAILED,
    HASH_MATCH_UNKNOWN,
    COMPONENT_MISSING_HASH,
    COMPONENT_MISSING_HASH_AND_MATCH_UNKNOWN
}
