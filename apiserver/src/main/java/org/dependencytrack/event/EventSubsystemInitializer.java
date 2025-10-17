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
package org.dependencytrack.event;

import alpine.Config;
import alpine.common.logging.Logger;
import alpine.event.LdapSyncEvent;
import alpine.event.framework.EventService;
import alpine.event.framework.SingleThreadedEventService;
import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import org.dependencytrack.common.ConfigKey;
import org.dependencytrack.event.maintenance.ComponentMetadataMaintenanceEvent;
import org.dependencytrack.event.maintenance.MetricsMaintenanceEvent;
import org.dependencytrack.event.maintenance.ProjectMaintenanceEvent;
import org.dependencytrack.event.maintenance.TagMaintenanceEvent;
import org.dependencytrack.event.maintenance.VulnerabilityDatabaseMaintenanceEvent;
import org.dependencytrack.event.maintenance.VulnerabilityScanMaintenanceEvent;
import org.dependencytrack.event.maintenance.WorkflowMaintenanceEvent;
import org.dependencytrack.tasks.BomUploadProcessingTask;
import org.dependencytrack.tasks.CallbackTask;
import org.dependencytrack.tasks.CloneProjectTask;
import org.dependencytrack.tasks.CsafMirrorTask;
import org.dependencytrack.tasks.DefectDojoUploadTask;
import org.dependencytrack.tasks.EpssMirrorTask;
import org.dependencytrack.tasks.FortifySscUploadTask;
import org.dependencytrack.tasks.GitHubAdvisoryMirrorTask;
import org.dependencytrack.tasks.IntegrityAnalysisTask;
import org.dependencytrack.tasks.IntegrityMetaInitializerTask;
import org.dependencytrack.tasks.InternalComponentIdentificationTask;
import org.dependencytrack.tasks.KennaSecurityUploadTask;
import org.dependencytrack.tasks.LdapSyncTaskWrapper;
import org.dependencytrack.tasks.NistMirrorTask;
import org.dependencytrack.tasks.OsvMirrorTask;
import org.dependencytrack.tasks.PolicyEvaluationTask;
import org.dependencytrack.tasks.RepositoryMetaAnalysisTask;
import org.dependencytrack.tasks.TaskScheduler;
import org.dependencytrack.tasks.VexUploadProcessingTask;
import org.dependencytrack.tasks.VulnerabilityAnalysisTask;
import org.dependencytrack.tasks.maintenance.ComponentMetadataMaintenanceTask;
import org.dependencytrack.tasks.maintenance.MetricsMaintenanceTask;
import org.dependencytrack.tasks.maintenance.ProjectMaintenanceTask;
import org.dependencytrack.tasks.maintenance.TagMaintenanceTask;
import org.dependencytrack.tasks.maintenance.VulnerabilityDatabaseMaintenanceTask;
import org.dependencytrack.tasks.maintenance.VulnerabilityScanMaintenanceTask;
import org.dependencytrack.tasks.maintenance.WorkflowMaintenanceTask;
import org.dependencytrack.tasks.metrics.PortfolioMetricsUpdateTask;
import org.dependencytrack.tasks.metrics.ProjectMetricsUpdateTask;
import org.dependencytrack.tasks.metrics.VulnerabilityMetricsUpdateTask;
import org.dependencytrack.tasks.vulnerabilitypolicy.VulnerabilityPolicyFetchTask;

import java.time.Duration;

/**
 * Initializes the event subsystem and configures event subscribers.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public class EventSubsystemInitializer implements ServletContextListener {

    private static final Logger LOGGER = Logger.getLogger(EventSubsystemInitializer.class);

    // Starts the EventService
    private static final EventService EVENT_SERVICE = EventService.getInstance();

    // Starts the SingleThreadedEventService
    private static final SingleThreadedEventService EVENT_SERVICE_ST = SingleThreadedEventService.getInstance();

    private static final Duration DRAIN_TIMEOUT_DURATION =
            Duration.parse(Config.getInstance().getProperty(ConfigKey.ALPINE_WORKER_POOL_DRAIN_TIMEOUT_DURATION));

    /**
     * {@inheritDoc}
     */
    @Override
    public void contextInitialized(final ServletContextEvent event) {
        LOGGER.info("Initializing asynchronous event subsystem");

        EVENT_SERVICE.subscribe(BomUploadEvent.class, BomUploadProcessingTask.class);
        EVENT_SERVICE.subscribe(VexUploadEvent.class, VexUploadProcessingTask.class);
        EVENT_SERVICE.subscribe(LdapSyncEvent.class, LdapSyncTaskWrapper.class);
        EVENT_SERVICE.subscribe(GitHubAdvisoryMirrorEvent.class, GitHubAdvisoryMirrorTask.class);
        EVENT_SERVICE.subscribe(OsvMirrorEvent.class, OsvMirrorTask.class);
        EVENT_SERVICE.subscribe(CsafMirrorEvent.class, CsafMirrorTask.class);
        EVENT_SERVICE.subscribe(ProjectVulnerabilityAnalysisEvent.class, VulnerabilityAnalysisTask.class);
        EVENT_SERVICE.subscribe(PortfolioVulnerabilityAnalysisEvent.class, VulnerabilityAnalysisTask.class);
        EVENT_SERVICE.subscribe(ProjectRepositoryMetaAnalysisEvent.class, RepositoryMetaAnalysisTask.class);
        EVENT_SERVICE.subscribe(PortfolioRepositoryMetaAnalysisEvent.class, RepositoryMetaAnalysisTask.class);
        EVENT_SERVICE.subscribe(ProjectMetricsUpdateEvent.class, ProjectMetricsUpdateTask.class);
        EVENT_SERVICE.subscribe(PortfolioMetricsUpdateEvent.class, PortfolioMetricsUpdateTask.class);
        EVENT_SERVICE.subscribe(VulnerabilityMetricsUpdateEvent.class, VulnerabilityMetricsUpdateTask.class);
        EVENT_SERVICE.subscribe(CloneProjectEvent.class, CloneProjectTask.class);
        EVENT_SERVICE.subscribe(FortifySscUploadEventAbstract.class, FortifySscUploadTask.class);
        EVENT_SERVICE.subscribe(DefectDojoUploadEventAbstract.class, DefectDojoUploadTask.class);
        EVENT_SERVICE.subscribe(KennaSecurityUploadEventAbstract.class, KennaSecurityUploadTask.class);
        EVENT_SERVICE.subscribe(InternalComponentIdentificationEvent.class, InternalComponentIdentificationTask.class);
        EVENT_SERVICE.subscribe(CallbackEvent.class, CallbackTask.class);
        EVENT_SERVICE.subscribe(NistMirrorEvent.class, NistMirrorTask.class);
        EVENT_SERVICE.subscribe(VulnerabilityPolicyFetchEvent.class, VulnerabilityPolicyFetchTask.class);
        EVENT_SERVICE.subscribe(EpssMirrorEvent.class, EpssMirrorTask.class);
        EVENT_SERVICE.subscribe(ComponentPolicyEvaluationEvent.class, PolicyEvaluationTask.class);
        EVENT_SERVICE.subscribe(ProjectPolicyEvaluationEvent.class, PolicyEvaluationTask.class);
        EVENT_SERVICE.subscribe(IntegrityMetaInitializerEvent.class, IntegrityMetaInitializerTask.class);
        EVENT_SERVICE.subscribe(IntegrityAnalysisEvent.class, IntegrityAnalysisTask.class);

        // Execute maintenance tasks on the single-threaded event service.
        // This way, they are not blocked by, and don't block, actual processing tasks on the main event service.
        EVENT_SERVICE_ST.subscribe(ComponentMetadataMaintenanceEvent.class, ComponentMetadataMaintenanceTask.class);
        EVENT_SERVICE_ST.subscribe(MetricsMaintenanceEvent.class, MetricsMaintenanceTask.class);
        EVENT_SERVICE_ST.subscribe(TagMaintenanceEvent.class, TagMaintenanceTask.class);
        EVENT_SERVICE_ST.subscribe(VulnerabilityDatabaseMaintenanceEvent.class, VulnerabilityDatabaseMaintenanceTask.class);
        EVENT_SERVICE_ST.subscribe(VulnerabilityScanMaintenanceEvent.class, VulnerabilityScanMaintenanceTask.class);
        EVENT_SERVICE_ST.subscribe(WorkflowMaintenanceEvent.class, WorkflowMaintenanceTask.class);
        EVENT_SERVICE_ST.subscribe(ProjectMaintenanceEvent.class, ProjectMaintenanceTask.class);

        TaskScheduler.getInstance();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void contextDestroyed(final ServletContextEvent event) {
        LOGGER.info("Shutting down asynchronous event subsystem");
        TaskScheduler.getInstance().shutdown();

        EVENT_SERVICE.unsubscribe(BomUploadProcessingTask.class);
        EVENT_SERVICE.unsubscribe(VexUploadProcessingTask.class);
        EVENT_SERVICE.unsubscribe(LdapSyncTaskWrapper.class);
        EVENT_SERVICE.unsubscribe(GitHubAdvisoryMirrorTask.class);
        EVENT_SERVICE.unsubscribe(OsvMirrorTask.class);
        EVENT_SERVICE.unsubscribe(CsafMirrorTask.class);
        EVENT_SERVICE.unsubscribe(VulnerabilityAnalysisTask.class);
        EVENT_SERVICE.unsubscribe(RepositoryMetaAnalysisTask.class);
        EVENT_SERVICE.unsubscribe(ProjectMetricsUpdateTask.class);
        EVENT_SERVICE.unsubscribe(PortfolioMetricsUpdateTask.class);
        EVENT_SERVICE.unsubscribe(VulnerabilityMetricsUpdateTask.class);
        EVENT_SERVICE.unsubscribe(CloneProjectTask.class);
        EVENT_SERVICE.unsubscribe(FortifySscUploadTask.class);
        EVENT_SERVICE.unsubscribe(DefectDojoUploadTask.class);
        EVENT_SERVICE.unsubscribe(KennaSecurityUploadTask.class);
        EVENT_SERVICE.unsubscribe(InternalComponentIdentificationTask.class);
        EVENT_SERVICE.unsubscribe(CallbackTask.class);
        EVENT_SERVICE.unsubscribe(NistMirrorTask.class);
        EVENT_SERVICE.unsubscribe(EpssMirrorTask.class);
        EVENT_SERVICE.unsubscribe(PolicyEvaluationTask.class);
        EVENT_SERVICE.unsubscribe(IntegrityMetaInitializerTask.class);
        EVENT_SERVICE.unsubscribe(IntegrityAnalysisTask.class);
        EVENT_SERVICE.unsubscribe(VulnerabilityPolicyFetchTask.class);
        EVENT_SERVICE.shutdown(DRAIN_TIMEOUT_DURATION);

        EVENT_SERVICE_ST.unsubscribe(ComponentMetadataMaintenanceTask.class);
        EVENT_SERVICE_ST.unsubscribe(MetricsMaintenanceTask.class);
        EVENT_SERVICE_ST.unsubscribe(TagMaintenanceTask.class);
        EVENT_SERVICE_ST.unsubscribe(VulnerabilityDatabaseMaintenanceTask.class);
        EVENT_SERVICE_ST.unsubscribe(VulnerabilityScanMaintenanceTask.class);
        EVENT_SERVICE_ST.unsubscribe(WorkflowMaintenanceTask.class);
        EVENT_SERVICE_ST.unsubscribe(ProjectMaintenanceTask.class);
        EVENT_SERVICE_ST.shutdown(DRAIN_TIMEOUT_DURATION);
    }
}
