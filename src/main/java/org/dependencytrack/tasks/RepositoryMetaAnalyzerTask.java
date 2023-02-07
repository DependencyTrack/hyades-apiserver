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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.tasks;

import alpine.common.logging.Logger;
import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import org.dependencytrack.event.ComponentRepositoryMetaAnalysisEvent;
import org.dependencytrack.event.PortfolioRepositoryMetaAnalysisEvent;
import org.dependencytrack.event.ProjectRepositoryMetaAnalysisEvent;
import org.dependencytrack.event.kafka.KafkaEventDispatcher;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.persistence.QueryManager;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import java.util.HashMap;
import java.util.List;
import java.util.UUID;

/**
 * A {@link Subscriber} to {@link ProjectRepositoryMetaAnalysisEvent} and {@link PortfolioRepositoryMetaAnalysisEvent}
 * that submits components of a specific project, or all components in the entire portfolio, for repository meta
 * analysis.
 */
public class RepositoryMetaAnalyzerTask implements Subscriber {

    private static final Logger LOGGER = Logger.getLogger(RepositoryMetaAnalyzerTask.class);

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
                processPortfolio();
            } catch (Exception ex) {
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
            pm.getFetchPlan().setGroup(Component.FetchGroup.REPOSITORY_META_ANALYSIS.name());

            List<Component> components = fetchNextComponentsPage(pm, project, null);
            while (!components.isEmpty()) {
                for (final var component : components) {
                    kafkaEventDispatcher.dispatch(new ComponentRepositoryMetaAnalysisEvent(pm.detachCopy(component)));
                }

                final long lastId = components.get(components.size() - 1).getId();
                components = fetchNextComponentsPage(qm.getPersistenceManager(), project, lastId);
            }
        }

        LOGGER.info("All components of project %s submitted for repository meta analysis".formatted(projectUuid));
    }

    private void processPortfolio() throws Exception {
        LOGGER.info("Submitting all components in portfolio for repository meta analysis");

        try (final QueryManager qm = new QueryManager()) {
            final PersistenceManager pm = qm.getPersistenceManager();
            pm.getFetchPlan().setGroup(Component.FetchGroup.REPOSITORY_META_ANALYSIS.name());

            List<Component> components = fetchNextComponentsPage(pm, null, null);
            while (!components.isEmpty()) {
                for (final var component : components) {
                    kafkaEventDispatcher.dispatch(new ComponentRepositoryMetaAnalysisEvent(pm.detachCopy(component)));
                }

                final long lastId = components.get(components.size() - 1).getId();
                components = fetchNextComponentsPage(qm.getPersistenceManager(), null, lastId);
            }
        }

        LOGGER.info("All components in portfolio submitted for repository meta analysis");
    }

    private List<Component> fetchNextComponentsPage(final PersistenceManager pm, final Project project, final Long lastId) throws Exception {
        try (final Query<Component> query = pm.newQuery(Component.class)) {
            var filter = "project.active == :projectActive";
            var params = new HashMap<String, Object>();
            params.put("projectActive", true);
            if (project != null) {
                filter += " && project == :project";
                params.put("project", project);
            }
            if (lastId != null) {
                filter += " && id < :lastId";
                params.put("lastId", lastId);
            }
            query.setFilter(filter);
            query.setNamedParameters(params);
            query.setOrdering("id DESC");
            query.setRange(0, 500);
            return List.copyOf(query.executeList());
        }
    }

}
