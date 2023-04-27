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
package org.dependencytrack.search;

import alpine.common.logging.Logger;
import alpine.notification.NotificationLevel;
import org.apache.lucene.document.Document;
import org.apache.lucene.document.Field;
import org.apache.lucene.index.CorruptIndexException;
import org.apache.lucene.index.Term;
import org.dependencytrack.model.Project;
import org.dependencytrack.notification.NotificationConstants;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.util.NotificationUtil;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.UUID;

/**
 * Indexer for operating on projects.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public final class ProjectIndexer extends IndexManager implements ObjectIndexer<Project> {

    private static final Logger LOGGER = Logger.getLogger(ProjectIndexer.class);
    private static final ProjectIndexer INSTANCE = new ProjectIndexer();

    protected static ProjectIndexer getInstance() {
        return INSTANCE;
    }

    /**
     * Private constructor.
     */
    private ProjectIndexer() {
        super(IndexType.PROJECT);
    }

    @Override
    public String[] getSearchFields() {
        return IndexConstants.PROJECT_SEARCH_FIELDS;
    }

    /**
     * Adds a Project object to a Lucene index.
     *
     * @param project A persisted Project object.
     */
    public void add(final Project project) {
        add(new ProjectProjection(project.getId(), project.getUuid(), project.getName(), project.getVersion(), project.getDescription()));
    }

    private void add(final ProjectProjection project) {
        final Document doc = new Document();
        addField(doc, IndexConstants.PROJECT_UUID, project.uuid().toString(), Field.Store.YES, false);
        addField(doc, IndexConstants.PROJECT_NAME, project.name(), Field.Store.YES, true);
        addField(doc, IndexConstants.PROJECT_VERSION, project.version(), Field.Store.YES, false);
        addField(doc, IndexConstants.PROJECT_DESCRIPTION, project.description(), Field.Store.YES, true);

        /*
        // There's going to potentially be confidential information in the project properties. Do not index.

        final StringBuilder sb = new StringBuilder();
        if (project.getProperties() != null) {
            for (ProjectProperty property : project.getProperties()) {
                sb.append(property.getPropertyValue()).append(" ");
            }
        }

        addField(doc, IndexConstants.PROJECT_PROPERTIES, sb.toString().trim(), Field.Store.YES, true);
        */

        try {
            getIndexWriter().addDocument(doc);
        } catch (CorruptIndexException e) {
            handleCorruptIndexException(e);
        } catch (IOException e) {
            LOGGER.error("An error occurred while adding a project to the index", e);
            String content = "An error occurred while adding a project to the index. Check log for details. " + e.getMessage();
            NotificationUtil.dispatchExceptionNotifications(NotificationScope.SYSTEM, NotificationGroup.INDEXING_SERVICE, NotificationConstants.Title.PROJECT_INDEXER, content, NotificationLevel.ERROR);
        }
    }

    /**
     * Deletes a Project object from the Lucene index.
     *
     * @param project A persisted Project object.
     */
    public void remove(final Project project) {
        try {
            getIndexWriter().deleteDocuments(new Term(IndexConstants.PROJECT_UUID, project.getUuid().toString()));
        } catch (CorruptIndexException e) {
            handleCorruptIndexException(e);
        } catch (IOException e) {
            LOGGER.error("An error occurred while removing a project from the index", e);
            String content = "An error occurred while removing a project from the index. Check log for details. " + e.getMessage();
            NotificationUtil.dispatchExceptionNotifications(NotificationScope.SYSTEM, NotificationGroup.INDEXING_SERVICE, NotificationConstants.Title.PROJECT_INDEXER, content, NotificationLevel.ERROR);
        }
    }

    /**
     * Re-indexes all Project objects.
     *
     * @since 3.4.0
     */
    public void reindex() {
        LOGGER.info("Starting reindex task. This may take some time.");
        super.reindex();
        try (final QueryManager qm = new QueryManager()) {
            final PersistenceManager pm = qm.getPersistenceManager();
            List<ProjectProjection> projects = fetchNextProjectsPage(pm, null);
            while (!projects.isEmpty()) {
                for (final ProjectProjection project : projects) {
                    add(project);
                }

                final long lastId = projects.get(projects.size() - 1).id();
                projects = fetchNextProjectsPage(pm, lastId);
            }
            commit();
        }
        LOGGER.info("Reindexing complete");
    }

    private List<ProjectProjection> fetchNextProjectsPage(final PersistenceManager pm, final Long lastId) {
        final Query<Project> query = pm.newQuery(Project.class);
        try {
            var filter = "active == :active";
            var params = new HashMap<String, Object>();
            params.put("active", true);
            if (lastId != null) {
                filter += " && id < :lastId";
                params.put("lastId", lastId);
            }
            query.setFilter(filter);
            query.setNamedParameters(params);
            query.setOrdering("id DESC");
            query.setRange(0, 2500);
            query.setResult("id, uuid, name, version, description");
            return List.copyOf(query.executeResultList(ProjectProjection.class));
        } finally {
            query.closeAll();
        }
    }

    public record ProjectProjection(long id, UUID uuid, String name, String version, String description) {
    }

}
