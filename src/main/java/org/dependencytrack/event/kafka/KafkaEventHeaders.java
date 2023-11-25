package org.dependencytrack.event.kafka;

import org.dependencytrack.model.VulnerabilityAnalysisLevel;
import org.dependencytrack.proto.vulnanalysis.v1.ScanCommand;

/**
 * Well-known headers for Kafka events published and / or consumed by Dependency-Track.
 */
public final class KafkaEventHeaders {

    /**
     * Optional header that may be used to communicate the {@link VulnerabilityAnalysisLevel}
     * along with {@link ScanCommand}s for vulnerability analysis.
     */
    public static final String VULN_ANALYSIS_LEVEL = "x-dtrack-vuln-analysis-level";
    public static final String IS_NEW_COMPONENT = "x-dtrack-is-new-component";

}
