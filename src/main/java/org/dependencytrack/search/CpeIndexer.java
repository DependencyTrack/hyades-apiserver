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
import org.dependencytrack.model.Cpe;
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
 * Indexer for operating on CPEs.
 *
 * @author Steve Springett
 * @since 3.6.0
 */
public final class CpeIndexer extends IndexManager implements ObjectIndexer<Cpe> {

    private static final Logger LOGGER = Logger.getLogger(CpeIndexer.class);
    private static final CpeIndexer INSTANCE = new CpeIndexer();

    protected static CpeIndexer getInstance() {
        return INSTANCE;
    }

    /**
     * Private constructor.
     */
    private CpeIndexer() {
        super(IndexType.CPE);
    }

    @Override
    public String[] getSearchFields() {
        return IndexConstants.CPE_SEARCH_FIELDS;
    }

    /**
     * Adds a Cpe object to a Lucene index.
     *
     * @param cpe A persisted Cpe object.
     */
    public void add(final Cpe cpe) {
        add(new CpeProjection(cpe.getId(), cpe.getUuid(), cpe.getCpe22(), cpe.getCpe23(),
                cpe.getVendor(), cpe.getProduct(), cpe.getVersion()));
    }

    private void add(final CpeProjection cpe) {
        final Document doc = new Document();
        addField(doc, IndexConstants.CPE_UUID, cpe.uuid().toString(), Field.Store.YES, false);
        addField(doc, IndexConstants.CPE_22, cpe.cpe22(), Field.Store.YES, true);
        addField(doc, IndexConstants.CPE_23, cpe.cpe23(), Field.Store.YES, true);
        addField(doc, IndexConstants.CPE_VENDOR, cpe.vendor(), Field.Store.YES, true);
        addField(doc, IndexConstants.CPE_PRODUCT, cpe.product(), Field.Store.YES, true);
        addField(doc, IndexConstants.CPE_VERSION, cpe.version(), Field.Store.YES, true);

        try {
            getIndexWriter().addDocument(doc);
        } catch (CorruptIndexException e) {
            handleCorruptIndexException(e);
        } catch (IOException e) {
            LOGGER.error("An error occurred while adding a CPE to the index", e);
            String content = "An error occurred while adding a CPE to the index. Check log for details. " + e.getMessage();
            NotificationUtil.dispatchExceptionNotifications(NotificationScope.SYSTEM, NotificationGroup.INDEXING_SERVICE, NotificationConstants.Title.CPE_INDEXER, content , NotificationLevel.ERROR);
        }
    }

    /**
     * Deletes a Cpe object from the Lucene index.
     *
     * @param cpe A persisted Cpe object.
     */
    public void remove(final Cpe cpe) {
        try {
            getIndexWriter().deleteDocuments(new Term(IndexConstants.CPE_UUID, cpe.getUuid().toString()));
        } catch (CorruptIndexException e) {
            handleCorruptIndexException(e);
        } catch (IOException e) {
            LOGGER.error("An error occurred while removing a CPE from the index", e);
            String content = "An error occurred while removing a CPE from the index. Check log for details. " + e.getMessage();
            NotificationUtil.dispatchExceptionNotifications(NotificationScope.SYSTEM, NotificationGroup.INDEXING_SERVICE, NotificationConstants.Title.CPE_INDEXER, content , NotificationLevel.ERROR);
        }
    }

    /**
     * Re-indexes all CPE objects.
     */
    public void reindex() {
        LOGGER.info("Starting reindex task. This may take some time.");
        super.reindex();
        try (QueryManager qm = new QueryManager()) {
            final PersistenceManager pm = qm.getPersistenceManager();
            List<CpeProjection> cpes = fetchNextCpesPage(pm, null);
            while (!cpes.isEmpty()) {
                for (final CpeProjection cpe : cpes) {
                    add(cpe);
                }

                final long lastId = cpes.get(cpes.size() - 1).id();
                cpes = fetchNextCpesPage(pm, lastId);
            }
            commit();
        }
        LOGGER.info("Reindexing complete");
    }

    private List<CpeProjection> fetchNextCpesPage(final PersistenceManager pm, final Long lastId) {
        final Query<Cpe> query = pm.newQuery(Cpe.class);
        try {
            if (lastId != null) {
                query.setFilter("id < :lastId");
                query.setNamedParameters(Map.of("lastId", lastId));
            }
            query.setOrdering("id DESC");
            query.setRange(0, 2500);
            query.setResult("id, uuid, cpe22, cpe23, vendor, product, version");
            return List.copyOf(query.executeResultList(CpeProjection.class));
        } finally {
            query.closeAll();
        }
    }

    public record CpeProjection(long id, UUID uuid, String cpe22, String cpe23, String vendor,
                                String product, String version) {
    }

}
