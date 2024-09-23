/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.tasks;

import alpine.event.LdapSyncEvent;
import alpine.event.framework.Event;
import alpine.server.tasks.LdapSyncTask;
import com.asahaf.javacron.Schedule;
import org.dependencytrack.event.CsafMirrorEvent;
import org.dependencytrack.event.DefectDojoUploadEventAbstract;
import org.dependencytrack.event.EpssMirrorEvent;
import org.dependencytrack.event.FortifySscUploadEventAbstract;
import org.dependencytrack.event.GitHubAdvisoryMirrorEvent;
import org.dependencytrack.event.IntegrityMetaInitializerEvent;
import org.dependencytrack.event.InternalComponentIdentificationEvent;
import org.dependencytrack.event.KennaSecurityUploadEventAbstract;
import org.dependencytrack.event.NistMirrorEvent;
import org.dependencytrack.event.OsvMirrorEvent;
import org.dependencytrack.event.PortfolioMetricsUpdateEvent;
import org.dependencytrack.event.PortfolioRepositoryMetaAnalysisEvent;
import org.dependencytrack.event.PortfolioVulnerabilityAnalysisEvent;
import org.dependencytrack.event.VulnerabilityMetricsUpdateEvent;
import org.dependencytrack.event.VulnerabilityPolicyFetchEvent;
import org.dependencytrack.event.maintenance.ComponentMetadataMaintenanceEvent;
import org.dependencytrack.event.maintenance.MetricsMaintenanceEvent;
import org.dependencytrack.event.maintenance.ProjectMaintenanceEvent;
import org.dependencytrack.event.maintenance.TagMaintenanceEvent;
import org.dependencytrack.event.maintenance.VulnerabilityDatabaseMaintenanceEvent;
import org.dependencytrack.event.maintenance.VulnerabilityScanMaintenanceEvent;
import org.dependencytrack.event.maintenance.WorkflowMaintenanceEvent;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.tasks.maintenance.ComponentMetadataMaintenanceTask;
import org.dependencytrack.tasks.maintenance.MetricsMaintenanceTask;
import org.dependencytrack.tasks.maintenance.ProjectMaintenanceTask;
import org.dependencytrack.tasks.maintenance.TagMaintenanceTask;
import org.dependencytrack.tasks.maintenance.VulnerabilityDatabaseMaintenanceTask;
import org.dependencytrack.tasks.maintenance.VulnerabilityScanMaintenanceTask;
import org.dependencytrack.tasks.maintenance.WorkflowMaintenanceTask;
import org.dependencytrack.tasks.metrics.PortfolioMetricsUpdateTask;
import org.dependencytrack.tasks.metrics.VulnerabilityMetricsUpdateTask;
import org.dependencytrack.tasks.vulnerabilitypolicy.VulnerabilityPolicyFetchTask;

import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.dependencytrack.model.ConfigPropertyConstants.*;
import static org.dependencytrack.util.TaskUtil.getCronScheduleForTask;

/**
 * @author Steve Springett
 * @since 3.0.0
 */
public final class TaskScheduler extends BaseTaskScheduler {

    // Holds an instance of TaskScheduler
    private static final TaskScheduler INSTANCE = new TaskScheduler();

    /**
     * Private constructor.
     */
    private TaskScheduler() {
        final Map<Event, Schedule> eventScheduleMap = Map.ofEntries(
                Map.entry(new VulnerabilityPolicyFetchEvent(), getCronScheduleForTask(VulnerabilityPolicyFetchTask.class)),
                Map.entry(new LdapSyncEvent(), getCronScheduleForTask(LdapSyncTask.class)),
                Map.entry(new NistMirrorEvent(), getCronScheduleForTask(NistMirrorTask.class)),
                Map.entry(new OsvMirrorEvent(null), getCronScheduleForTask(OsvMirrorTask.class)),
                Map.entry(new CsafMirrorEvent(), getCronScheduleForTask(CsafMirrorTask.class)),
                Map.entry(new GitHubAdvisoryMirrorEvent(), getCronScheduleForTask(GitHubAdvisoryMirrorTask.class)),
                Map.entry(new EpssMirrorEvent(), getCronScheduleForTask(EpssMirrorTask.class)),
                Map.entry(new PortfolioMetricsUpdateEvent(), getCronScheduleForTask(PortfolioMetricsUpdateTask.class)),
                Map.entry(new VulnerabilityMetricsUpdateEvent(), getCronScheduleForTask(VulnerabilityMetricsUpdateTask.class)),
                Map.entry(new InternalComponentIdentificationEvent(), getCronScheduleForTask(InternalComponentIdentificationTask.class)),
                Map.entry(new PortfolioVulnerabilityAnalysisEvent(), getCronScheduleForTask(VulnerabilityAnalysisTask.class)),
                Map.entry(new PortfolioRepositoryMetaAnalysisEvent(), getCronScheduleForTask(RepositoryMetaAnalysisTask.class)),
                Map.entry(new IntegrityMetaInitializerEvent(), getCronScheduleForTask(IntegrityMetaInitializerTask.class)),
                Map.entry(new ComponentMetadataMaintenanceEvent(), getCronScheduleForTask(ComponentMetadataMaintenanceTask.class)),
                Map.entry(new MetricsMaintenanceEvent(), getCronScheduleForTask(MetricsMaintenanceTask.class)),
                Map.entry(new TagMaintenanceEvent(), getCronScheduleForTask(TagMaintenanceTask.class)),
                Map.entry(new VulnerabilityDatabaseMaintenanceEvent(), getCronScheduleForTask(VulnerabilityDatabaseMaintenanceTask.class)),
                Map.entry(new VulnerabilityScanMaintenanceEvent(), getCronScheduleForTask(VulnerabilityScanMaintenanceTask.class)),
                Map.entry(new WorkflowMaintenanceEvent(), getCronScheduleForTask(WorkflowMaintenanceTask.class)),
                Map.entry(new ProjectMaintenanceEvent(), getCronScheduleForTask(ProjectMaintenanceTask.class)));

        Map<Event, Schedule> configurableTasksMap = new HashMap<>();
        if (isTaskEnabled(FORTIFY_SSC_ENABLED)) {
            configurableTasksMap.put(new FortifySscUploadEventAbstract(), getCronScheduleForTask(FortifySscUploadTask.class));
        }
        if (isTaskEnabled(DEFECTDOJO_ENABLED)) {
            configurableTasksMap.put(new DefectDojoUploadEventAbstract(), getCronScheduleForTask(DefectDojoUploadTask.class));
        }
        if (isTaskEnabled(KENNA_ENABLED)) {
            configurableTasksMap.put(new KennaSecurityUploadEventAbstract(), getCronScheduleForTask(KennaSecurityUploadTask.class));
        }

        final Map<Event, Schedule> mergedEventScheduleMap = Stream.concat(
                        eventScheduleMap.entrySet().stream(),
                        configurableTasksMap.entrySet().stream())
                .collect(Collectors.toMap(
                        Map.Entry::getKey,
                        Map.Entry::getValue));

        scheduleTask(mergedEventScheduleMap);
    }

    /**
     * Return an instance of the TaskScheduler instance.
     *
     * @return a TaskScheduler instance
     */
    public static TaskScheduler getInstance() {
        return INSTANCE;
    }

    private boolean isTaskEnabled(final ConfigPropertyConstants enabledConstraint) {
        try (final var qm = new QueryManager()) {
            return qm.isEnabled(enabledConstraint);
        }
    }
}
