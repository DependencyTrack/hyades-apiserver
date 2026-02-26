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
import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import org.dependencytrack.common.pagination.PageIterator;
import org.dependencytrack.csaf.CsafProviderDao;
import org.dependencytrack.csaf.ImportCsafDocumentsWorkflow;
import org.dependencytrack.csaf.ListCsafProvidersQuery;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.dex.engine.api.request.CreateWorkflowRunRequest;
import org.dependencytrack.event.DefectDojoUploadEventAbstract;
import org.dependencytrack.event.EpssMirrorEvent;
import org.dependencytrack.event.FortifySscUploadEventAbstract;
import org.dependencytrack.event.GitHubAdvisoryMirrorEvent;
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
import org.dependencytrack.event.maintenance.WorkflowMaintenanceEvent;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.proto.internal.workflow.v1.ImportCsafDocumentsArg;
import org.dependencytrack.tasks.maintenance.ComponentMetadataMaintenanceTask;
import org.dependencytrack.tasks.maintenance.MetricsMaintenanceTask;
import org.dependencytrack.tasks.maintenance.ProjectMaintenanceTask;
import org.dependencytrack.tasks.maintenance.TagMaintenanceTask;
import org.dependencytrack.tasks.maintenance.VulnerabilityDatabaseMaintenanceTask;
import org.dependencytrack.tasks.maintenance.WorkflowMaintenanceTask;
import org.dependencytrack.tasks.metrics.PortfolioMetricsUpdateTask;
import org.dependencytrack.tasks.metrics.VulnerabilityMetricsUpdateTask;
import org.dependencytrack.tasks.vulnerabilitypolicy.VulnerabilityPolicyFetchTask;
import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.model.ConfigPropertyConstants.DEFECTDOJO_ENABLED;
import static org.dependencytrack.model.ConfigPropertyConstants.FORTIFY_SSC_ENABLED;
import static org.dependencytrack.model.ConfigPropertyConstants.KENNA_ENABLED;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;
import static org.dependencytrack.util.TaskUtil.getCronScheduleForTask;
import static org.dependencytrack.util.TaskUtil.getCronScheduleFromConfig;

/**
 * @since 5.7.0
 */
public final class TaskSchedulerInitializer implements ServletContextListener {

    private static final Logger LOGGER = LoggerFactory.getLogger(TaskSchedulerInitializer.class);

    private final Config config;
    private final TaskScheduler scheduler;

    TaskSchedulerInitializer(Config config, TaskScheduler scheduler) {
        this.config = config;
        this.scheduler = scheduler;
    }

    @SuppressWarnings("unused")
    public TaskSchedulerInitializer() {
        this(ConfigProvider.getConfig(), new TaskScheduler());
    }

    @Override
    public void contextInitialized(ServletContextEvent event) {
        if (!config.getOptionalValue("dt.task-scheduler.enabled", boolean.class).orElse(true)) {
            LOGGER.info("Not starting task scheduler because it is disabled");
            return;
        }

        LOGGER.info("Starting task scheduler");
        scheduler.start();

        final var dexEngine = (DexEngine) event.getServletContext().getAttribute(DexEngine.class.getName());
        requireNonNull(dexEngine, "dexEngine has not been initialized");

        scheduler
                .schedule(
                        "Component Metadata Maintenance",
                        getCronScheduleForTask(ComponentMetadataMaintenanceTask.class),
                        () -> Event.dispatch(new ComponentMetadataMaintenanceEvent()))
                .schedule(
                        "CSAF Document Import",
                        getCronScheduleFromConfig(config, "task.csaf.document.import.cron"),
                        () -> {
                            final List<? extends CreateWorkflowRunRequest<?>> requests =
                                    withJdbiHandle(handle -> PageIterator.stream(
                                                    pageToken -> handle.attach(CsafProviderDao.class).list(
                                                            new ListCsafProvidersQuery()
                                                                    .withEnabled(true)
                                                                    .withPageToken(pageToken)))
                                            .map(provider -> new CreateWorkflowRunRequest<>(ImportCsafDocumentsWorkflow.class)
                                                    .withWorkflowInstanceId("import-csaf-documents:" + provider.getId())
                                                    .withArgument(ImportCsafDocumentsArg.newBuilder()
                                                            .setProviderId(provider.getId().toString())
                                                            .build()))
                                            .toList());
                            dexEngine.createRuns(requests);
                        })
                .schedule(
                        "Defect Dojo Upload",
                        getCronScheduleForTask(DefectDojoUploadTask.class),
                        () -> {
                            try (final var qm = new QueryManager()) {
                                if (qm.isEnabled(DEFECTDOJO_ENABLED)) {
                                    Event.dispatch(new DefectDojoUploadEventAbstract());
                                }
                            }
                        })
                .schedule(
                        "EPSS Mirror",
                        getCronScheduleForTask(EpssMirrorTask.class),
                        () -> Event.dispatch(new EpssMirrorEvent()))
                .schedule(
                        "Fortify SSC Upload",
                        getCronScheduleForTask(FortifySscUploadTask.class),
                        () -> {
                            try (final var qm = new QueryManager()) {
                                if (qm.isEnabled(FORTIFY_SSC_ENABLED)) {
                                    Event.dispatch(new FortifySscUploadEventAbstract());
                                }
                            }
                        })
                .schedule(
                        "GitHub Advisories Mirror",
                        getCronScheduleForTask(GitHubAdvisoryMirrorTask.class),
                        () -> Event.dispatch(new GitHubAdvisoryMirrorEvent()))
                .schedule(
                        "Internal Component Identification",
                        getCronScheduleForTask(InternalComponentIdentificationTask.class),
                        () -> Event.dispatch(new InternalComponentIdentificationEvent()))
                .schedule(
                        "Kenna Security Upload",
                        getCronScheduleForTask(KennaSecurityUploadTask.class),
                        () -> {
                            try (final var qm = new QueryManager()) {
                                if (qm.isEnabled(KENNA_ENABLED)) {
                                    Event.dispatch(new KennaSecurityUploadEventAbstract());
                                }
                            }
                        })
                .schedule(
                        "LDAP Sync",
                        getCronScheduleForTask(LdapSyncTask.class),
                        () -> Event.dispatch(new LdapSyncEvent()))
                .schedule(
                        "Metrics Maintenance",
                        getCronScheduleForTask(MetricsMaintenanceTask.class),
                        () -> Event.dispatch(new MetricsMaintenanceEvent()))
                .schedule(
                        "NVD Mirror",
                        getCronScheduleForTask(NistMirrorTask.class),
                        () -> Event.dispatch(new NistMirrorEvent()))
                .schedule(
                        "OSV Mirror",
                        getCronScheduleForTask(OsvMirrorTask.class),
                        () -> Event.dispatch(new OsvMirrorEvent()))
                .schedule(
                        "Portfolio Metrics Update",
                        getCronScheduleForTask(PortfolioMetricsUpdateTask.class),
                        () -> Event.dispatch(new PortfolioMetricsUpdateEvent()))
                .schedule(
                        "Portfolio Repository Meta Analysis",
                        getCronScheduleForTask(RepositoryMetaAnalysisTask.class),
                        () -> Event.dispatch(new PortfolioRepositoryMetaAnalysisEvent()))
                .schedule(
                        "Portfolio Vulnerability Analysis",
                        getCronScheduleForTask(VulnerabilityAnalysisTask.class),
                        () -> Event.dispatch(new PortfolioVulnerabilityAnalysisEvent()))
                .schedule(
                        "Project Maintenance",
                        getCronScheduleForTask(ProjectMaintenanceTask.class),
                        () -> Event.dispatch(new ProjectMaintenanceEvent()))
                .schedule(
                        "Tag Maintenance",
                        getCronScheduleForTask(TagMaintenanceTask.class),
                        () -> Event.dispatch(new TagMaintenanceEvent()))
                .schedule(
                        "Vulnerability Database Maintenance",
                        getCronScheduleForTask(VulnerabilityDatabaseMaintenanceTask.class),
                        () -> Event.dispatch(new VulnerabilityDatabaseMaintenanceEvent()))
                .schedule(
                        "Vulnerability Metrics Update",
                        getCronScheduleForTask(VulnerabilityMetricsUpdateTask.class),
                        () -> Event.dispatch(new VulnerabilityMetricsUpdateEvent()))
                .schedule(
                        "Vulnerability Policy Sync",
                        getCronScheduleForTask(VulnerabilityPolicyFetchTask.class),
                        () -> Event.dispatch(new VulnerabilityPolicyFetchEvent()))
                .schedule(
                        "Workflow Maintenance",
                        getCronScheduleForTask(WorkflowMaintenanceTask.class),
                        () -> Event.dispatch(new WorkflowMaintenanceEvent()));
    }

    @Override
    public void contextDestroyed(ServletContextEvent sce) {
        LOGGER.info("Stopping task scheduler");
        scheduler.close();
    }

}
