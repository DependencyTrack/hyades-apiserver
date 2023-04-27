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
import org.dependencytrack.model.License;
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
 * Indexer for operating on licenses.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public final class LicenseIndexer extends IndexManager implements ObjectIndexer<License> {

    private static final Logger LOGGER = Logger.getLogger(LicenseIndexer.class);
    private static final LicenseIndexer INSTANCE = new LicenseIndexer();

    protected static LicenseIndexer getInstance() {
        return INSTANCE;
    }

    /**
     * Private constructor.
     */
    private LicenseIndexer() {
        super(IndexType.LICENSE);
    }

    @Override
    public String[] getSearchFields() {
        return IndexConstants.LICENSE_SEARCH_FIELDS;
    }

    /**
     * Adds a License object to a Lucene index.
     *
     * @param license A persisted License object.
     */
    public void add(final License license) {
        add(new LicenseProjection(license.getId(), license.getUuid(), license.getLicenseId(), license.getName()));
    }

    private void add(final LicenseProjection license) {
        final Document doc = new Document();
        addField(doc, IndexConstants.LICENSE_UUID, license.uuid().toString(), Field.Store.YES, false);
        addField(doc, IndexConstants.LICENSE_LICENSEID, license.licenseId(), Field.Store.YES, true);
        addField(doc, IndexConstants.LICENSE_NAME, license.name(), Field.Store.YES, true);

        try {
            getIndexWriter().addDocument(doc);
        } catch (CorruptIndexException e) {
            handleCorruptIndexException(e);
        } catch (IOException e) {
            LOGGER.error("An error occurred while adding a license to the index", e);
            String content = "An error occurred while adding a license to the index. Check log for details. " + e.getMessage();
            NotificationUtil.dispatchExceptionNotifications(NotificationScope.SYSTEM, NotificationGroup.INDEXING_SERVICE, NotificationConstants.Title.LICENSE_INDEXER, content, NotificationLevel.ERROR);
        }
    }

    /**
     * Deletes a License object from the Lucene index.
     *
     * @param license A persisted License object.
     */
    public void remove(final License license) {
        try {
            getIndexWriter().deleteDocuments(new Term(IndexConstants.LICENSE_UUID, license.getUuid().toString()));
        } catch (CorruptIndexException e) {
            handleCorruptIndexException(e);
        } catch (IOException e) {
            LOGGER.error("An error occurred while removing a license from the index", e);
            String content = "An error occurred while removing a license from the index. Check log for details. " + e.getMessage();
            NotificationUtil.dispatchExceptionNotifications(NotificationScope.SYSTEM, NotificationGroup.INDEXING_SERVICE, NotificationConstants.Title.LICENSE_INDEXER, content, NotificationLevel.ERROR);

        }
    }

    /**
     * Re-indexes all License objects.
     *
     * @since 3.4.0
     */
    public void reindex() {
        LOGGER.info("Starting reindex task. This may take some time.");
        super.reindex();
        try (QueryManager qm = new QueryManager()) {
            final PersistenceManager pm = qm.getPersistenceManager();
            List<LicenseProjection> licenses = fetchNextLicensesPage(pm, null);
            while (!licenses.isEmpty()) {
                for (final LicenseProjection license : licenses) {
                    add(license);
                }

                final long lastId = licenses.get(licenses.size() - 1).id();
                licenses = fetchNextLicensesPage(pm, lastId);
            }
            commit();
        }
        LOGGER.info("Reindexing complete");
    }

    private List<LicenseProjection> fetchNextLicensesPage(final PersistenceManager pm, final Long lastId) {
        final Query<License> query = pm.newQuery(License.class);
        try {
            if (lastId != null) {
                query.setFilter("id < :lastId");
                query.setNamedParameters(Map.of("lastId", lastId));
            }
            query.setOrdering("id DESC");
            query.setRange(0, 2500);
            query.setResult("id, uuid, licenseId, name");
            return List.copyOf(query.executeResultList(LicenseProjection.class));
        } finally {
            query.closeAll();
        }
    }

    public record LicenseProjection(long id, UUID uuid, String licenseId, String name) {
    }

}
