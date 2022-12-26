package org.dependencytrack.event.kafka.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

public class AnalyzerCompletionStatus{
    boolean snykCompleted;
    boolean OSSCompleted;
    boolean internalCompleted;

    boolean internalAnalyzerCompletedForCpe;

    public boolean isInternalAnalyzerCompletedForCpe() {
        return internalAnalyzerCompletedForCpe;
    }

    public void setInternalAnalyzerCompletedForCpe(boolean internalAnalyzerCompletedForCpe) {
        this.internalAnalyzerCompletedForCpe = internalAnalyzerCompletedForCpe;
    }

    public boolean isSnykCompleted() {
        return snykCompleted;
    }

    public void setSnykCompleted(boolean snykCompleted) {
        this.snykCompleted = snykCompleted;
    }

    public boolean isOSSCompleted() {
        return OSSCompleted;
    }

    public void setOSSCompleted(boolean OSSCompleted) {
        this.OSSCompleted = OSSCompleted;
    }

    public boolean isInternalCompleted() {
        return internalCompleted;
    }

    public void setInternalCompleted(boolean internalCompleted) {
        this.internalCompleted = internalCompleted;
    }
}
