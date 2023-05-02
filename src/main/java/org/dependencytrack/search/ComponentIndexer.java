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
import org.dependencytrack.model.Component;
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
 * Indexer for operating on components.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public final class ComponentIndexer extends IndexManager implements ObjectIndexer<Component> {

    private static final Logger LOGGER = Logger.getLogger(ComponentIndexer.class);
    private static final ComponentIndexer INSTANCE = new ComponentIndexer();

    protected static ComponentIndexer getInstance() {
        return INSTANCE;
    }

    /**
     * Private constructor.
     */
    private ComponentIndexer() {
        super(IndexType.COMPONENT);
    }

    @Override
    public String[] getSearchFields() {
        return IndexConstants.COMPONENT_SEARCH_FIELDS;
    }

    /**
     * Adds a Component object to a Lucene index.
     *
     * @param component A persisted Component object.
     */
    public void add(final Component component) {
        add(new ComponentProjection(component.getId(), component.getUuid(), component.getGroup(),
                component.getName(), component.getVersion(), component.getDescription(), component.getSha1()));
    }

    private void add(final ComponentProjection component) {
        final Document doc = new Document();
        addField(doc, IndexConstants.COMPONENT_UUID, component.uuid().toString(), Field.Store.YES, false);
        addField(doc, IndexConstants.COMPONENT_NAME, component.name(), Field.Store.YES, true);
        addField(doc, IndexConstants.COMPONENT_GROUP, component.group(), Field.Store.YES, true);
        addField(doc, IndexConstants.COMPONENT_VERSION, component.version(), Field.Store.YES, false);
        addField(doc, IndexConstants.COMPONENT_SHA1, component.sha1(), Field.Store.YES, true);
        addField(doc, IndexConstants.COMPONENT_DESCRIPTION, component.description(), Field.Store.YES, true);

        try {
            getIndexWriter().addDocument(doc);
        } catch (CorruptIndexException e) {
            handleCorruptIndexException(e);
        } catch (IOException e) {
            LOGGER.error("An error occurred while adding component to index", e);
            String content = "An error occurred while adding component to index. Check log for details. " + e.getMessage();
            NotificationUtil.dispatchExceptionNotifications(NotificationScope.SYSTEM, NotificationGroup.INDEXING_SERVICE, NotificationConstants.Title.COMPONENT_INDEXER, content, NotificationLevel.ERROR);
        }
    }

    /**
     * Deletes a Component object from the Lucene index.
     *
     * @param component A persisted Component object.
     */
    public void remove(final Component component) {
        try {
            getIndexWriter().deleteDocuments(new Term(IndexConstants.COMPONENT_UUID, component.getUuid().toString()));
        } catch (CorruptIndexException e) {
            handleCorruptIndexException(e);
        } catch (IOException e) {
            LOGGER.error("An error occurred while removing a component from the index", e);
            String content = "An error occurred while removing a component from the index. Check log for details. " + e.getMessage();
            NotificationUtil.dispatchExceptionNotifications(NotificationScope.SYSTEM, NotificationGroup.INDEXING_SERVICE, NotificationConstants.Title.COMPONENT_INDEXER, content, NotificationLevel.ERROR);
        }
    }

    /**
     * Re-indexes all Component objects.
     *
     * @since 3.4.0
     */
    public void reindex() {
        LOGGER.info("Starting reindex task. This may take some time.");
        super.reindex();
        try (final QueryManager qm = new QueryManager()) {
            final PersistenceManager pm = qm.getPersistenceManager();
            List<ComponentProjection> components = fetchNextComponentsPage(pm, null);
            while (!components.isEmpty()) {
                for (final ComponentProjection component : components) {
                    add(component);
                }

                final long lastId = components.get(components.size() - 1).id();
                components = fetchNextComponentsPage(pm, lastId);
            }
            commit();
        }
        LOGGER.info("Reindexing complete");
    }

    private List<ComponentProjection> fetchNextComponentsPage(final PersistenceManager pm, final Long lastId) {
        final Query<Component> query = pm.newQuery(Component.class);
        try {
            var filter = "project.active == :projectActive";
            var params = new HashMap<String, Object>();
            params.put("projectActive", true);
            if (lastId != null) {
                filter += " && id < :lastId";
                params.put("lastId", lastId);
            }
            query.setFilter(filter);
            query.setNamedParameters(params);
            query.setOrdering("id DESC");
            query.setRange(0, 2500);
            query.setResult("id, uuid, \"group\", name, version, description, sha1");
            return List.copyOf(query.executeResultList(ComponentProjection.class));
        } finally {
            query.closeAll();
        }
    }

    public record ComponentProjection(long id, UUID uuid, String group, String name,
                                      String version, String description, String sha1) {
    }

}
