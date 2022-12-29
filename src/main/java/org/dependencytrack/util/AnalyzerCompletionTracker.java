package org.dependencytrack.util;

import org.dependencytrack.event.kafka.dto.AnalyzerCompletionStatus;
import org.dependencytrack.event.kafka.dto.AnalyzerConfig;

import java.util.List;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public class AnalyzerCompletionTracker {

    public static ConcurrentHashMap<UUID, AnalyzerConfig> analyzerConfigMap = new ConcurrentHashMap<>();
    public static ConcurrentHashMap<UUID, AnalyzerCompletionStatus> completionTrackMap = new ConcurrentHashMap<>();

    public static ConcurrentHashMap<Long, List<UUID>> projectComponentsMap = new ConcurrentHashMap<Long, java.util.List<UUID>>();
}
