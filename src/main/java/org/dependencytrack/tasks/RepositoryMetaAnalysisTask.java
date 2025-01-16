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

import alpine.common.logging.Logger;
import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import net.javacrumbs.shedlock.core.LockConfiguration;
import net.javacrumbs.shedlock.core.LockExtender;
import net.javacrumbs.shedlock.core.LockingTaskExecutor;
import org.dependencytrack.event.ComponentRepositoryMetaAnalysisEvent;
import org.dependencytrack.event.PortfolioRepositoryMetaAnalysisEvent;
import org.dependencytrack.event.ProjectRepositoryMetaAnalysisEvent;
import org.dependencytrack.event.kafka.KafkaEventDispatcher;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.proto.repometaanalysis.v1.FetchMeta;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.UUID;

import static org.dependencytrack.util.LockProvider.executeWithLock;
import static org.dependencytrack.util.LockProvider.isTaskLockToBeExtended;
import static org.dependencytrack.util.TaskUtil.getLockConfigForTask;

/**
 * A {@link Subscriber} to {@link ProjectRepositoryMetaAnalysisEvent} and {@link PortfolioRepositoryMetaAnalysisEvent}
 * that submits components of a specific project, or all components in the entire portfolio, for repository meta
 * analysis.
 * <p>
 * As repository metadata analysis is purely based on PURLs, and does not (currently) consider PURL qualifiers,
 * components are submitted by distinct PURL coordinates. As such, there is no 1:1 correlation between total number
 * of components in the portfolio or project, and records submitted for analysis.
 */
public class RepositoryMetaAnalysisTask implements Subscriber {

    private static final Logger LOGGER = Logger.getLogger(RepositoryMetaAnalysisTask.class);

    private final KafkaEventDispatcher kafkaEventDispatcher = new KafkaEventDispatcher();

    /**
     * {@inheritDoc}
     */
    public void inform(final Event e) {
        if (e instanceof final ProjectRepositoryMetaAnalysisEvent event) {
            try {
                processProject(event.projectUuid());
            } catch (Exception ex) {
                LOGGER.error("""
                        An unexpected error occurred while submitting components of\s
                        project %s for repository meta analysis
                        """.formatted(event.projectUuid()), ex);
            }
        } else if (e instanceof PortfolioRepositoryMetaAnalysisEvent) {
            try {
                executeWithLock(
                        getLockConfigForTask(RepositoryMetaAnalysisTask.class),
                        (LockingTaskExecutor.Task) this::processPortfolio);
            } catch (Throwable ex) {
                LOGGER.error("An unexpected error occurred while submitting components for repository meta analysis", ex);
            }
        }
    }

    private void processProject(final UUID projectUuid) throws Exception {
        LOGGER.info("Submitting components of project %s for repository meta analysis".formatted(projectUuid));

        try (final var qm = new QueryManager()) {
            final Project project = qm.getObjectByUuid(Project.class, projectUuid);
            if (project == null) {
                LOGGER.error("A project with UUID %s does not exist".formatted(projectUuid));
                return;
            }

            final PersistenceManager pm = qm.getPersistenceManager();

            long offset = 0;
            List<ComponentProjection> components = fetchNextComponentsPage(pm, project, offset);
            while (!components.isEmpty()) {
                //latest version information needs to be fetched for project as either triggered because of fresh bom upload or individual project reanalysis
                dispatchComponents(components);

                offset += components.size();
                components = fetchNextComponentsPage(pm, project, offset);
            }
        }

        LOGGER.info("All components of project %s submitted for repository meta analysis".formatted(projectUuid));
    }

    private void processPortfolio() throws Exception {
        LOGGER.info("Submitting all components in portfolio for repository meta analysis");

        LockConfiguration lockConfiguration = getLockConfigForTask(RepositoryMetaAnalysisTask.class);

        try (final QueryManager qm = new QueryManager()) {
            final PersistenceManager pm = qm.getPersistenceManager();

            long offset = 0;
            long startTime = System.currentTimeMillis();
            List<ComponentProjection> components = fetchNextComponentsPage(pm, null, offset);
            while (!components.isEmpty()) {
                long cumulativeProcessingTime = System.currentTimeMillis() - startTime;
                if (isTaskLockToBeExtended(cumulativeProcessingTime, RepositoryMetaAnalysisTask.class)) {
                    LockExtender.extendActiveLock(Duration.ofMinutes(5).plus(lockConfiguration.getLockAtLeastFor()), lockConfiguration.getLockAtLeastFor());
                }
                //latest version information does not need to be fetched for project as triggered for portfolio means it is a scheduled event happening
                dispatchComponents(components);

                offset += components.size();
                components = fetchNextComponentsPage(pm, null, offset);
            }
        }

        LOGGER.info("All components in portfolio submitted for repository meta analysis");
    }

    private void dispatchComponents(final List<ComponentProjection> components) {
        for (final var component : components) {
            kafkaEventDispatcher.dispatchEvent(new ComponentRepositoryMetaAnalysisEvent(null, component.purlCoordinates(), component.internal(), FetchMeta.FETCH_META_LATEST_VERSION));
        }
    }

    private List<ComponentProjection> fetchNextComponentsPage(final PersistenceManager pm, final Project project, final long offset) throws Exception {
        try (final Query<Component> query = pm.newQuery(Component.class)) {
            var filter = "project.inactiveSince == null && purlCoordinates != null";
            var params = new HashMap<String, Object>();
            if (project != null) {
                filter += " && project == :project";
                params.put("project", project);
            }
            query.setFilter(filter);
            query.setNamedParameters(params);
            query.setOrdering("purlCoordinates ASC"); // Keep the order somewhat consistent
            query.setRange(offset, offset + 5000);
            query.setResult("DISTINCT purlCoordinates, internal");
            return List.copyOf(query.executeResultList(ComponentProjection.class));
        }
    }

    public record ComponentProjection(String purlCoordinates, Boolean internal) {
    }

}
