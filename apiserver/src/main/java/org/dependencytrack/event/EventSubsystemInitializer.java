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

import alpine.common.logging.Logger;
import alpine.event.LdapSyncEvent;
import alpine.event.framework.EventService;
import alpine.event.framework.SingleThreadedEventService;
import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.event.kafka.KafkaEventDispatcher;
import org.dependencytrack.event.maintenance.ComponentMetadataMaintenanceEvent;
import org.dependencytrack.event.maintenance.MetricsMaintenanceEvent;
import org.dependencytrack.event.maintenance.ProjectMaintenanceEvent;
import org.dependencytrack.event.maintenance.TagMaintenanceEvent;
import org.dependencytrack.event.maintenance.VulnerabilityDatabaseMaintenanceEvent;
import org.dependencytrack.event.maintenance.VulnerabilityScanMaintenanceEvent;
import org.dependencytrack.event.maintenance.WorkflowMaintenanceEvent;
import org.dependencytrack.plugin.PluginManager;
import org.dependencytrack.tasks.BomUploadProcessingTask;
import org.dependencytrack.tasks.CallbackTask;
import org.dependencytrack.tasks.CloneProjectTask;
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
import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;

import java.time.Duration;
import java.util.concurrent.TimeoutException;

import static java.util.Objects.requireNonNull;

/**
 * Initializes the event subsystem and configures event subscribers.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public class EventSubsystemInitializer implements ServletContextListener {

    private static final Logger LOGGER = Logger.getLogger(EventSubsystemInitializer.class);

    private final Config config;
    private final EventService eventService;
    private final SingleThreadedEventService singleThreadedEventService;

    EventSubsystemInitializer(
            Config config,
            EventService eventService,
            SingleThreadedEventService singleThreadedEventService) {
        this.config = config;
        this.eventService = eventService;
        this.singleThreadedEventService = singleThreadedEventService;
    }

    @SuppressWarnings("unused") // Used by servlet context.
    public EventSubsystemInitializer() {
        this(ConfigProvider.getConfig(), EventService.getInstance(), SingleThreadedEventService.getInstance());
    }

    @Override
    public void contextInitialized(ServletContextEvent event) {
        LOGGER.info("Initializing asynchronous event subsystem");

        final var kafkaEventDispatcher = new KafkaEventDispatcher();

        final var dexEngine = (DexEngine) event.getServletContext().getAttribute(DexEngine.class.getName());
        requireNonNull(dexEngine, "dexEngine has not been initialized");

        final var pluginManager = (PluginManager) event.getServletContext().getAttribute(PluginManager.class.getName());
        requireNonNull(pluginManager, "pluginManager has not been initialized");

        eventService.subscribe(
                BomUploadEvent.class,
                new BomUploadProcessingTask(
                        dexEngine,
                        pluginManager,
                        kafkaEventDispatcher,
                        config.getOptionalValue("tmp.delay.bom.processed.notification", boolean.class).orElse(false)));
        eventService.subscribe(VexUploadEvent.class, new VexUploadProcessingTask());
        eventService.subscribe(LdapSyncEvent.class, new LdapSyncTaskWrapper());
        eventService.subscribe(GitHubAdvisoryMirrorEvent.class, new GitHubAdvisoryMirrorTask(pluginManager));
        eventService.subscribe(OsvMirrorEvent.class, new OsvMirrorTask(pluginManager));
        eventService.subscribe(ProjectVulnerabilityAnalysisEvent.class, new VulnerabilityAnalysisTask());
        eventService.subscribe(PortfolioVulnerabilityAnalysisEvent.class, new VulnerabilityAnalysisTask());
        eventService.subscribe(ProjectRepositoryMetaAnalysisEvent.class, new RepositoryMetaAnalysisTask());
        eventService.subscribe(PortfolioRepositoryMetaAnalysisEvent.class, new RepositoryMetaAnalysisTask());
        eventService.subscribe(ProjectMetricsUpdateEvent.class, new ProjectMetricsUpdateTask());
        eventService.subscribe(PortfolioMetricsUpdateEvent.class, new PortfolioMetricsUpdateTask());
        eventService.subscribe(VulnerabilityMetricsUpdateEvent.class, new VulnerabilityMetricsUpdateTask());
        eventService.subscribe(CloneProjectEvent.class, new CloneProjectTask());
        eventService.subscribe(FortifySscUploadEventAbstract.class, new FortifySscUploadTask());
        eventService.subscribe(DefectDojoUploadEventAbstract.class, new DefectDojoUploadTask());
        eventService.subscribe(KennaSecurityUploadEventAbstract.class, new KennaSecurityUploadTask());
        eventService.subscribe(InternalComponentIdentificationEvent.class, new InternalComponentIdentificationTask());
        eventService.subscribe(CallbackEvent.class, new CallbackTask());
        eventService.subscribe(NistMirrorEvent.class, new NistMirrorTask(pluginManager));
        eventService.subscribe(VulnerabilityPolicyFetchEvent.class, new VulnerabilityPolicyFetchTask());
        eventService.subscribe(EpssMirrorEvent.class, new EpssMirrorTask());
        eventService.subscribe(ComponentPolicyEvaluationEvent.class, new PolicyEvaluationTask());
        eventService.subscribe(ProjectPolicyEvaluationEvent.class, new PolicyEvaluationTask());
        eventService.subscribe(IntegrityMetaInitializerEvent.class, new IntegrityMetaInitializerTask());
        eventService.subscribe(IntegrityAnalysisEvent.class, new IntegrityAnalysisTask());

        // Execute maintenance tasks on the single-threaded event service.
        // This way, they are not blocked by, and don't block, actual processing tasks on the main event service.
        singleThreadedEventService.subscribe(ComponentMetadataMaintenanceEvent.class, new ComponentMetadataMaintenanceTask());
        singleThreadedEventService.subscribe(MetricsMaintenanceEvent.class, new MetricsMaintenanceTask());
        singleThreadedEventService.subscribe(TagMaintenanceEvent.class, new TagMaintenanceTask());
        singleThreadedEventService.subscribe(VulnerabilityDatabaseMaintenanceEvent.class, new VulnerabilityDatabaseMaintenanceTask());
        singleThreadedEventService.subscribe(VulnerabilityScanMaintenanceEvent.class, new VulnerabilityScanMaintenanceTask());
        singleThreadedEventService.subscribe(WorkflowMaintenanceEvent.class, new WorkflowMaintenanceTask());
        singleThreadedEventService.subscribe(ProjectMaintenanceEvent.class, new ProjectMaintenanceTask());
    }

    @Override
    public void contextDestroyed(ServletContextEvent event) {
        LOGGER.info("Shutting down asynchronous event subsystem");

        final var drainTimeout = config
                .getOptionalValue("alpine.worker.pool.drain.timeout.duration", Duration.class)
                .orElse(Duration.ofSeconds(30));

        eventService.unsubscribe(BomUploadProcessingTask.class);
        eventService.unsubscribe(VexUploadProcessingTask.class);
        eventService.unsubscribe(LdapSyncTaskWrapper.class);
        eventService.unsubscribe(GitHubAdvisoryMirrorTask.class);
        eventService.unsubscribe(OsvMirrorTask.class);
        eventService.unsubscribe(VulnerabilityAnalysisTask.class);
        eventService.unsubscribe(RepositoryMetaAnalysisTask.class);
        eventService.unsubscribe(ProjectMetricsUpdateTask.class);
        eventService.unsubscribe(PortfolioMetricsUpdateTask.class);
        eventService.unsubscribe(VulnerabilityMetricsUpdateTask.class);
        eventService.unsubscribe(CloneProjectTask.class);
        eventService.unsubscribe(FortifySscUploadTask.class);
        eventService.unsubscribe(DefectDojoUploadTask.class);
        eventService.unsubscribe(KennaSecurityUploadTask.class);
        eventService.unsubscribe(InternalComponentIdentificationTask.class);
        eventService.unsubscribe(CallbackTask.class);
        eventService.unsubscribe(NistMirrorTask.class);
        eventService.unsubscribe(EpssMirrorTask.class);
        eventService.unsubscribe(PolicyEvaluationTask.class);
        eventService.unsubscribe(IntegrityMetaInitializerTask.class);
        eventService.unsubscribe(IntegrityAnalysisTask.class);
        eventService.unsubscribe(VulnerabilityPolicyFetchTask.class);
        try {
            eventService.shutdown(drainTimeout);
        } catch (TimeoutException e) {
            LOGGER.warn("Failed to shut down event service", e);
        }

        singleThreadedEventService.unsubscribe(ComponentMetadataMaintenanceTask.class);
        singleThreadedEventService.unsubscribe(MetricsMaintenanceTask.class);
        singleThreadedEventService.unsubscribe(TagMaintenanceTask.class);
        singleThreadedEventService.unsubscribe(VulnerabilityDatabaseMaintenanceTask.class);
        singleThreadedEventService.unsubscribe(VulnerabilityScanMaintenanceTask.class);
        singleThreadedEventService.unsubscribe(WorkflowMaintenanceTask.class);
        singleThreadedEventService.unsubscribe(ProjectMaintenanceTask.class);
        try {
            singleThreadedEventService.shutdown(drainTimeout);
        } catch (TimeoutException e) {
            LOGGER.warn("Failed to shut down single-threaded event service", e);
        }
    }
}
