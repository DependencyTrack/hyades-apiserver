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
import org.dependencytrack.model.ServiceComponent;
import org.dependencytrack.notification.NotificationConstants;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.util.NotificationUtil;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Indexer for operating on services.
 *
 * @author Steve Springett
 * @since 4.2.0
 */
public final class ServiceComponentIndexer extends IndexManager implements ObjectIndexer<ServiceComponent> {

    private static final Logger LOGGER = Logger.getLogger(ServiceComponentIndexer.class);
    private static final ServiceComponentIndexer INSTANCE = new ServiceComponentIndexer();

    protected static ServiceComponentIndexer getInstance() {
        return INSTANCE;
    }

    /**
     * Private constructor.
     */
    private ServiceComponentIndexer() {
        super(IndexType.SERVICECOMPONENT);
    }

    @Override
    public String[] getSearchFields() {
        return IndexConstants.SERVICECOMPONENT_SEARCH_FIELDS;
    }

    /**
     * Adds a Component object to a Lucene index.
     *
     * @param service A persisted ServiceComponent object.
     */
    public void add(final ServiceComponent service) {
        add(new ServiceComponentProjection(service.getId(), service.getUuid(), service.getGroup(),
                service.getName(), service.getVersion(), service.getDescription()));
    }

    private void add(final ServiceComponentProjection serviceComponent) {
        final Document doc = new Document();
        addField(doc, IndexConstants.SERVICECOMPONENT_UUID, serviceComponent.uuid().toString(), Field.Store.YES, false);
        addField(doc, IndexConstants.SERVICECOMPONENT_NAME, serviceComponent.name(), Field.Store.YES, true);
        addField(doc, IndexConstants.SERVICECOMPONENT_GROUP, serviceComponent.group(), Field.Store.YES, true);
        addField(doc, IndexConstants.SERVICECOMPONENT_VERSION, serviceComponent.version(), Field.Store.YES, false);
        // TODO: addField(doc, IndexConstants.SERVICECOMPONENT_URL, service.getUrl(), Field.Store.YES, true);
        addField(doc, IndexConstants.SERVICECOMPONENT_DESCRIPTION, serviceComponent.description(), Field.Store.YES, true);

        try {
            getIndexWriter().addDocument(doc);
        } catch (CorruptIndexException e) {
            handleCorruptIndexException(e);
        } catch (IOException e) {
            LOGGER.error("An error occurred while adding service to index", e);
            String content = "An error occurred while adding service to index. Check log for details. " + e.getMessage();
            NotificationUtil.dispatchExceptionNotifications(NotificationScope.SYSTEM, NotificationGroup.INDEXING_SERVICE, NotificationConstants.Title.SERVICECOMPONENT_INDEXER, content , NotificationLevel.ERROR);
        }
    }

    /**
     * Deletes a ServiceComponent object from the Lucene index.
     *
     * @param service A persisted ServiceComponent object.
     */
    public void remove(final ServiceComponent service) {
        try {
            getIndexWriter().deleteDocuments(new Term(IndexConstants.SERVICECOMPONENT_UUID, service.getUuid().toString()));
        } catch (CorruptIndexException e) {
            handleCorruptIndexException(e);
        } catch (IOException e) {
            LOGGER.error("An error occurred while removing a service from the index", e);
            String content = "An error occurred while removing a service from the index. Check log for details. " + e.getMessage();
            NotificationUtil.dispatchExceptionNotifications(NotificationScope.SYSTEM, NotificationGroup.INDEXING_SERVICE, NotificationConstants.Title.SERVICECOMPONENT_INDEXER, content , NotificationLevel.ERROR);
        }
    }

    /**
     * Re-indexes all ServiceComponent objects.
     * @since 4.2.0
     */
    public void reindex() {
        LOGGER.info("Starting reindex task. This may take some time.");
        super.reindex();
        try (QueryManager qm = new QueryManager()) {
            final PersistenceManager pm = qm.getPersistenceManager();
            List<ServiceComponentProjection> serviceComponents = fetchNextServiceComponentsPage(pm, null);
            while (!serviceComponents.isEmpty()) {
                for (final ServiceComponentProjection serviceComponent : serviceComponents) {
                    add(serviceComponent);
                }

                final long lastId = serviceComponents.get(serviceComponents.size() - 1).id();
                serviceComponents = fetchNextServiceComponentsPage(pm, lastId);
            }
            commit();
        }
        LOGGER.info("Reindexing complete");
    }

    private List<ServiceComponentProjection> fetchNextServiceComponentsPage(final PersistenceManager pm, final Long lastId) {
        final Query<ServiceComponent> query = pm.newQuery(ServiceComponent.class);
        try {
            if (lastId != null) {
                query.setFilter("id < :lastId");
                query.setNamedParameters(Map.of("lastId", lastId));
            }
            query.setOrdering("id DESC");
            query.setRange(0, 2500);
            query.setResult("id, uuid, \"group\", name, version, description");
            return List.copyOf(query.executeResultList(ServiceComponentProjection.class));
        } finally {
            query.closeAll();
        }
    }

    public record ServiceComponentProjection(long id, UUID uuid, String group, String name, String version, String description) {
    }

}
