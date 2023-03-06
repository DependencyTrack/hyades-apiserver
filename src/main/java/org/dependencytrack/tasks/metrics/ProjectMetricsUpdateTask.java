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
package org.dependencytrack.tasks.metrics;

import alpine.common.logging.Logger;
import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import org.dependencytrack.event.ComponentMetricsUpdateEvent;
import org.dependencytrack.event.ProjectMetricsUpdateEvent;
import org.dependencytrack.event.kafka.KafkaEventDispatcher;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.DependencyMetrics;
import org.dependencytrack.model.Project;
import org.dependencytrack.persistence.QueryManager;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.UUID;

/**
 * A {@link Subscriber} task that updates {@link Project} metrics.
 *
 * @since 4.6.0
 */
public class ProjectMetricsUpdateTask implements Subscriber {

    private static final Logger LOGGER = Logger.getLogger(ProjectMetricsUpdateTask.class);

    @Override
    public void inform(final Event e) {
        if (e instanceof final ProjectMetricsUpdateEvent event) {
            try {
                updateMetrics(event.getUuid());
            } catch (Exception ex) {
                LOGGER.error("An unexpected error occurred while updating metrics for project " + event.getUuid(), ex);
            }
        }
    }

    public static void updateMetrics(final UUID uuid) throws Exception {
        LOGGER.info("Executing metrics update for project " + uuid);
        try (final QueryManager qm = new QueryManager()) {
            final PersistenceManager pm = qm.getPersistenceManager();

            final Project project = qm.getObjectByUuid(Project.class, uuid, List.of(Project.FetchGroup.METRICS_UPDATE.name()));
            if (project == null) {
                throw new NoSuchElementException("Project " + uuid + " does not exist");
            }

            LOGGER.debug("Fetching first components page for project " + uuid);
            List<Component> components = fetchNextComponentsPage(pm, project, null);

            while (!components.isEmpty()) {
                for (final Component component : components) {
                    DependencyMetrics metrics = ComponentMetricsUpdateTask.getComponentMetrics(component.getUuid());
                    new KafkaEventDispatcher().dispatch(new ComponentMetricsUpdateEvent(component.getUuid(), metrics));
                }

                LOGGER.debug("Fetching next components page for project " + uuid);
                final long lastId = components.get(components.size() - 1).getId();
                components = fetchNextComponentsPage(pm, project, lastId);
            }
        }
    }

    public static void deleteComponents(final UUID uuid) throws Exception {
        LOGGER.info("Deleting components for project " + uuid);
        try (final QueryManager qm = new QueryManager()) {
            final PersistenceManager pm = qm.getPersistenceManager();

            final Project project = qm.getObjectByUuid(Project.class, uuid, List.of(Project.FetchGroup.METRICS_UPDATE.name()));
            if (project == null) {
                throw new NoSuchElementException("Project " + uuid + " does not exist");
            }

            LOGGER.debug("Fetching first components page for project " + uuid);
            List<Component> components = fetchNextComponentsPage(pm, project, null);

            while (!components.isEmpty()) {
                for (final Component component : components) {
                    new KafkaEventDispatcher().dispatch(new ComponentMetricsUpdateEvent(component.getUuid(), null));
                }
                LOGGER.debug("Fetching next components page for project " + uuid);
                final long lastId = components.get(components.size() - 1).getId();
                components = fetchNextComponentsPage(pm, project, lastId);
            }
        }
    }

    private static List<Component> fetchNextComponentsPage(final PersistenceManager pm, final Project project, final Long lastId) throws Exception {
        try (final Query<Component> query = pm.newQuery(Component.class)) {
            if (lastId == null) {
                query.setFilter("project == :project");
                query.setParameters(project);
            } else {
                query.setFilter("project == :project && id < :lastId");
                query.setParameters(project, lastId);
            }
            query.setOrdering("id DESC");
            query.setRange(0, 500);
            query.getFetchPlan().setGroup(Component.FetchGroup.METRICS_UPDATE.name());
            return List.copyOf(query.executeList());
        }
    }

}
