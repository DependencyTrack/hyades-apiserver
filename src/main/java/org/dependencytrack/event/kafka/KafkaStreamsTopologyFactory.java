package org.dependencytrack.event.kafka;

import alpine.event.framework.ChainableEvent;
import alpine.event.framework.Event;
import alpine.notification.Notification;
import alpine.notification.NotificationLevel;
import org.apache.kafka.common.serialization.Serdes;
import org.apache.kafka.streams.KeyValue;
import org.apache.kafka.streams.StreamsBuilder;
import org.apache.kafka.streams.StreamsConfig;
import org.apache.kafka.streams.Topology;
import org.apache.kafka.streams.kstream.Consumed;
import org.apache.kafka.streams.kstream.KStream;
import org.apache.kafka.streams.kstream.Named;
import org.apache.kafka.streams.kstream.Repartitioned;
import org.datanucleus.PropertyNames;
import org.dependencytrack.event.ComponentMetricsUpdateEvent;
import org.dependencytrack.event.ComponentPolicyEvaluationEvent;
import org.dependencytrack.event.ProjectMetricsUpdateEvent;
import org.dependencytrack.event.ProjectPolicyEvaluationEvent;
import org.dependencytrack.event.kafka.processor.MirrorVulnerabilityProcessor;
import org.dependencytrack.event.kafka.processor.RepositoryMetaResultProcessor;
import org.dependencytrack.event.kafka.processor.VulnerabilityScanResultProcessor;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAlias;
import org.dependencytrack.model.VulnerabilityScan;
import org.dependencytrack.notification.NotificationConstants;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.persistence.QueryManager;
import org.hyades.proto.vulnanalysis.v1.ScanKey;
import org.hyades.proto.vulnanalysis.v1.ScanResult;

import java.math.BigDecimal;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

class KafkaStreamsTopologyFactory {

    Topology createTopology() {
        final var streamsBuilder = new StreamsBuilder();

        final var streamsProperties = new Properties();
        streamsProperties.put(StreamsConfig.TOPOLOGY_OPTIMIZATION_CONFIG, StreamsConfig.OPTIMIZE);

        final KStream<ScanKey, ScanResult> vulnScanResultStream = streamsBuilder
                .stream(KafkaTopics.VULN_ANALYSIS_RESULT.name(), Consumed
                        .with(KafkaTopics.VULN_ANALYSIS_RESULT.keySerde(), KafkaTopics.VULN_ANALYSIS_RESULT.valueSerde())
                        .withName("consume_from_%s_topic".formatted(KafkaTopics.VULN_ANALYSIS_RESULT.name())));

        // Process the vulnerabilities reported by the scanners.
        final KStream<ScanKey, ScanResult> processedVulnScanResultStream = vulnScanResultStream
                .processValues(VulnerabilityScanResultProcessor::new, Named.as("process_vuln_scan_result"));

        // Re-key processed results to their respective scan token, and record their arrival.
        final KStream<String, VulnerabilityScan> completedVulnScanStream = processedVulnScanResultStream
                .map((scanKey, scanResult) -> {
                    // Drop scanner results, as they can be rather large, and we don't need them anymore.
                    // Dropping them will save us some compression and network overhead during the repartition.
                    // We can remove this step should we ever need access to the results again.
                    final var strippedScanResult = ScanResult.newBuilder(scanResult).clearScannerResults().build();
                    return KeyValue.pair(scanKey.getScanToken(), strippedScanResult);
                }, Named.as("re-key_scan-result_to_scan-token"))
                .repartition(Repartitioned
                        .with(Serdes.String(), KafkaTopics.VULN_ANALYSIS_RESULT.valueSerde())
                        .withName("processed-vuln-scan-result-by-scan-token"))
                .mapValues((scanToken, value) -> {
                    try (final var qm = new QueryManager().withL2CacheDisabled()) {
                        // Detach VulnerabilityScan objects when committing changes. Without this,
                        // all fields except the ID field will be unloaded on commit (the object will become HOLLOW),
                        // causing the call to getStatus() to trigger a database query behind the scenes.
                        qm.getPersistenceManager().setProperty(PropertyNames.PROPERTY_DETACH_ALL_ON_COMMIT, "true");

                        final VulnerabilityScan vulnScan = qm.recordVulnerabilityScanResult(scanToken);
                        if (vulnScan == null || vulnScan.getStatus() != VulnerabilityScan.Status.COMPLETED) {
                            // When the vulnerability scan is not completed, we don't care about it.
                            // We'll filter out nulls in the next filter step.
                            return null;
                        }

                        return vulnScan;
                    }
                }, Named.as("record_processed_vuln_scan_result"))
                .filter((scanToken, vulnScan) -> vulnScan != null,
                        Named.as("filter_completed_vuln_scans"));
        completedVulnScanStream.foreach((scantoken, vulnscan) -> {
            if (vulnscan.getTargetIdentifier().toString().equals(VulnerabilityScan.TargetType.PROJECT.toString())) {
                sendNotificationForCompletedVulnerabilityScan(vulnscan);
            }});

        completedVulnScanStream
                .foreach((scanToken, vulnScan) -> {
                    final ChainableEvent policyEvaluationEvent = switch (vulnScan.getTargetType()) {
                        case COMPONENT -> new ComponentPolicyEvaluationEvent(vulnScan.getTargetIdentifier());
                        case PROJECT -> new ProjectPolicyEvaluationEvent(vulnScan.getTargetIdentifier());
                    };
                    policyEvaluationEvent.setChainIdentifier(UUID.fromString(vulnScan.getToken()));

                    // Trigger a metrics update no matter if the policy evaluation succeeded or not.
                    final Event metricsUpdateEvent = switch (vulnScan.getTargetType()) {
                        case COMPONENT -> new ComponentMetricsUpdateEvent(vulnScan.getTargetIdentifier());
                        case PROJECT -> new ProjectMetricsUpdateEvent(vulnScan.getTargetIdentifier());
                    };
                    policyEvaluationEvent.onFailure(metricsUpdateEvent);
                    policyEvaluationEvent.onSuccess(metricsUpdateEvent);

                    Event.dispatch(policyEvaluationEvent);
                }, Named.as("trigger_policy_evaluation"));

        streamsBuilder
                .stream(KafkaTopics.REPO_META_ANALYSIS_RESULT.name(),
                        Consumed.with(KafkaTopics.REPO_META_ANALYSIS_RESULT.keySerde(), KafkaTopics.REPO_META_ANALYSIS_RESULT.valueSerde())
                                .withName("consume_from_%s_topic".formatted(KafkaTopics.REPO_META_ANALYSIS_RESULT.name())))
                .process(RepositoryMetaResultProcessor::new, Named.as("process_repo_meta_analysis_result"));

        streamsBuilder
                .stream(KafkaTopics.NEW_VULNERABILITY.name(),
                        Consumed.with(KafkaTopics.NEW_VULNERABILITY.keySerde(), KafkaTopics.NEW_VULNERABILITY.valueSerde())
                                .withName("consume_from_%s_topic".formatted(KafkaTopics.NEW_VULNERABILITY.name())))
                .process(MirrorVulnerabilityProcessor::new, Named.as("process_mirror_vulnerability"));

        return streamsBuilder.build(streamsProperties);
    }

    private void sendNotificationForCompletedVulnerabilityScan( VulnerabilityScan vulnscan ) {
                try (QueryManager qm = new QueryManager()) {
                    Project project = qm.getObjectByUuid(Project.class, vulnscan.getTargetIdentifier());
                    List<Component> componentList = qm.getAllComponents(project);
                    ConcurrentHashMap<String, String> cumulativeContent = new ConcurrentHashMap<>();
                    for (Component component : componentList) {
                        ConcurrentHashMap<String, String> notificationContent = new ConcurrentHashMap<>();
                        List<Vulnerability> vulnerabilities = qm.getAllVulnerabilities(component);
                        if (!vulnerabilities.isEmpty()) {
                            notificationContent.put("Vulnerable Library", component.getName());
                            notificationContent.put("Vulnerable library version", component.getVersion());
                            notificationContent.put("Purl", component.getPurl().toString());
                            for (Vulnerability vulnerability : vulnerabilities) {
                                ConcurrentHashMap<String, String> vulnerabilityDetails = new ConcurrentHashMap<>();
                                if (!vulnerability.getAliases().isEmpty()) {
                                    for (VulnerabilityAlias vulnerabilityAlias : vulnerability.getAliases()) {
                                        vulnerabilityDetails.put("CVE ID", Optional.ofNullable(vulnerabilityAlias.getCveId()).orElse("NA"));
                                        vulnerabilityDetails.put("GHSA ID", Optional.ofNullable(vulnerabilityAlias.getGhsaId()).orElse("NA"));
                                        vulnerabilityDetails.put("OSV ID", Optional.ofNullable(vulnerabilityAlias.getOsvId()).orElse("NA"));
                                        vulnerabilityDetails.put("SNYK ID", Optional.ofNullable(vulnerabilityAlias.getSnykId()).orElse("NA"));
                                        vulnerabilityDetails.put("Sonatype ID", Optional.ofNullable(vulnerabilityAlias.getSonatypeId()).orElse("NA"));
                                        vulnerabilityDetails.put("VulnDb ID", Optional.ofNullable(vulnerabilityAlias.getVulnDbId()).orElse("NA"));
                                        vulnerabilityDetails.put("Gsd ID", Optional.ofNullable(vulnerabilityAlias.getGsdId()).orElse("NA"));
                                        vulnerabilityDetails.put("Internal ID", Optional.ofNullable(vulnerabilityAlias.getInternalId()).orElse("NA"));
                                    }
                                }
                                vulnerabilityDetails.put("CVSSV3Score", String.valueOf(Optional.ofNullable(vulnerability.getCvssV3BaseScore()).orElse(BigDecimal.valueOf(0L))));
                                vulnerabilityDetails.put("CVSSV2Score", String.valueOf(Optional.ofNullable(vulnerability.getCvssV2BaseScore()).orElse(BigDecimal.valueOf(0L))));
                                vulnerabilityDetails.put("Vulnerability id",vulnerability.getVulnId());
                                notificationContent.putAll(vulnerabilityDetails);
                            }

                        }
                        cumulativeContent.putAll(notificationContent);
                    }
                    StringBuilder contents = new StringBuilder();
                    for(Map.Entry<String, String> entry: cumulativeContent.entrySet()){
                        contents.append(entry.getKey()).append(": ").append(entry.getValue());
                    }
                    final KafkaEventDispatcher kafkaEventDispatcher = new KafkaEventDispatcher();
                    kafkaEventDispatcher.dispatchAsync(vulnscan.getTargetIdentifier(),
                            new Notification()
                                    .scope(NotificationScope.PORTFOLIO)
                                    .group(NotificationGroup.PROJECT_VULN_ANALYSIS_COMPLETE)
                                    .level(NotificationLevel.INFORMATIONAL)
                                    .title(NotificationConstants.Title.PROJECT_VULN_ANALYSIS_COMPLETE)
                                    .content(contents.toString())
                                    .subject("Vulnerability data for project "+project.getName()));
                }
    }

}
