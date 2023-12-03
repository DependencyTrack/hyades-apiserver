package org.dependencytrack.notification.persistence;

import org.dependencytrack.proto.notification.v1.Component;
import org.dependencytrack.proto.notification.v1.ComponentVulnAnalysisCompleteSubject;
import org.dependencytrack.proto.notification.v1.Project;
import org.dependencytrack.proto.notification.v1.ProjectVulnAnalysisCompleteSubject;
import org.dependencytrack.proto.notification.v1.ProjectVulnAnalysisStatus;
import org.dependencytrack.proto.notification.v1.Vulnerability;
import org.jdbi.v3.core.result.RowView;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.BiConsumer;
import java.util.function.BinaryOperator;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Collector;

import static org.dependencytrack.proto.notification.v1.ProjectVulnAnalysisStatus.PROJECT_VULN_ANALYSIS_STATUS_COMPLETED;
import static org.dependencytrack.proto.notification.v1.ProjectVulnAnalysisStatus.PROJECT_VULN_ANALYSIS_STATUS_FAILED;
import static org.dependencytrack.proto.notification.v1.ProjectVulnAnalysisStatus.PROJECT_VULN_ANALYSIS_STATUS_UNSPECIFIED;

public class ProjectVulnAnalysisCompleteSubjectCollector implements Collector<RowView, ProjectVulnAnalysisCompleteSubject.Builder, ProjectVulnAnalysisCompleteSubject> {

    private final Map<Component, List<Vulnerability>> vulnsByComponent = new HashMap<>();

    private String token;
    private Project project;
    private ProjectVulnAnalysisStatus status;

    @Override
    public Supplier<ProjectVulnAnalysisCompleteSubject.Builder> supplier() {
        return ProjectVulnAnalysisCompleteSubject::newBuilder;
    }

    @Override
    public BiConsumer<ProjectVulnAnalysisCompleteSubject.Builder, RowView> accumulator() {
        return (builder, rowView) -> {
            if (token == null) {
                token = rowView.getColumn("vulnScanToken", String.class);
            }
            if (project == null) {
                project = rowView.getRow(Project.class);
            }
            if (status == null) {
                status = switch (rowView.getColumn("vulnScanStatus", String.class)) {
                    case "COMPLETED" -> PROJECT_VULN_ANALYSIS_STATUS_COMPLETED;
                    case "FAILED" -> PROJECT_VULN_ANALYSIS_STATUS_FAILED;
                    default -> PROJECT_VULN_ANALYSIS_STATUS_UNSPECIFIED;
                };
            }

            final var component = rowView.getRow(Component.class);
            vulnsByComponent.compute(component, (c, vulns) -> {
                if (vulns == null) {
                    final var vulnsX = new ArrayList<Vulnerability>();
                    vulnsX.add(rowView.getRow(Vulnerability.class));
                    return vulnsX;
                } else {
                    vulns.add(rowView.getRow(Vulnerability.class));
                    return vulns;
                }
            });
        };
    }

    @Override
    public BinaryOperator<ProjectVulnAnalysisCompleteSubject.Builder> combiner() {
        return (builderA, builderB) -> builderA;
    }

    @Override
    public Function<ProjectVulnAnalysisCompleteSubject.Builder, ProjectVulnAnalysisCompleteSubject> finisher() {
        return builder -> builder
                .setToken(token)
                .setStatus(status)
                .setProject(project)
                .addAllFindings(vulnsByComponent.entrySet().stream()
                        .map(entry -> ComponentVulnAnalysisCompleteSubject.newBuilder()
                                .setComponent(entry.getKey())
                                .addAllVulnerabilities(entry.getValue())
                                .build())
                        .toList())
                .build();
    }

    @Override
    public Set<Characteristics> characteristics() {
        return Collections.emptySet();
    }

}
