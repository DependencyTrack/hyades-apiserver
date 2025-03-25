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
package org.dependencytrack.persistence;

import alpine.common.logging.Logger;
import alpine.persistence.PaginatedResult;
import alpine.resources.AlpineRequest;
import org.datanucleus.store.rdbms.query.ForwardQueryResult;
import org.dependencytrack.model.CsafDocumentEntity;
import org.dependencytrack.model.CsafSourceEntity;

import javax.annotation.Nullable;
import javax.jdo.JDOObjectNotFoundException;
import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.dependencytrack.util.PersistenceUtil.applyIfChanged;

public class CsafQueryManager extends QueryManager implements IQueryManager {
    private static final Logger LOGGER = Logger.getLogger(CsafQueryManager.class);

    /**
     * Constructs a new CsafQueryManager.
     *
     * @param pm a PersistenceManager object
     */
    CsafQueryManager(final PersistenceManager pm) {
        super(pm);
    }

    /**
     * Constructs a new CsafQueryManager.
     *
     * @param pm      a PersistenceManager object
     * @param request an AlpineRequest object
     */
    CsafQueryManager(final PersistenceManager pm, final AlpineRequest request) {
        super(pm, request);
    }


    /**
     * Retrieves a list of all persisted CSAF sources.
     *
     * @param isAggregator true if aggregators should be fetched, false if providers are to be shown.
     * @param isDiscovered true if discovered sources should be fetched, false if configured sources are to be shown.
     * @return list of csaf sources
     */
    @Override
    public PaginatedResult getCsafSources(boolean isAggregator, boolean isDiscovered) {
        final Query<CsafSourceEntity> query = pm.newQuery(CsafSourceEntity.class);
        query.filter("aggregator == :aggregator && discovery == :discovered");
        if (orderBy == null) query.setOrdering("id desc");

        return execute(query, isAggregator, isDiscovered);
    }

    /**
     * Creates a new CSAF Entity
     *
     * @param name    Name of the CSAF entity
     * @param url     URL of the configured source
     * @param enabled True, if source should be used for mirroring
     * @return the created CSAF entity
     */
    @Override
    public CsafSourceEntity createCsafSource(String name, String url, boolean enabled, boolean aggregator) {
        /*if (repositoryExist(type, identifier)) { // TODO check existing
            return null;
        }
        int order = 0;
        final List<Repository> existingRepos = getAllRepositoriesOrdered(type);
        if (existingRepos != null) {
            for (final Repository existing : existingRepos) {
                if (existing.getResolutionOrder() > order) {
                    order = existing.getResolutionOrder();
                }
            }
        }*/
        final CsafSourceEntity csaf = new CsafSourceEntity();
        csaf.setName(name);
        csaf.setUrl(url);
        csaf.setEnabled(enabled);
        csaf.setAggregator(aggregator);

        return persist(csaf);
    }

    @Override
    public CsafSourceEntity createCsafSourceFromFile(String name, String contents, boolean enabled, boolean aggregator) {
        final var csaf = new CsafSourceEntity();
        csaf.setName(name);
        csaf.setContent(contents);
        csaf.setEnabled(enabled);
        csaf.setAggregator(aggregator);
        return persist(csaf);
    }

    /**
     * Synchronizes a batch of {@link CsafDocumentEntity} records.
     *
     * @param list the batch of {@link CsafDocumentEntity} records to synchronize
     */
    public void synchronizeAllCsafDocuments(List<CsafDocumentEntity> list) {
        runInTransaction(() -> {
            for (final CsafDocumentEntity doc : list) {
                synchronizeCsafDocument(doc);
            }
        });
    }

    /**
     * Synchronizes a {{@link CsafDocumentEntity}}. This method first checks if the record
     * already exists and updates it. If it does exist, it will create a new record.
     *
     * @param csaf The CSAF document to synchronize
     * @return a CSAF document entity
     */
    public CsafDocumentEntity synchronizeCsafDocument(CsafDocumentEntity csaf) {
        CsafDocumentEntity result = updateCsafDocument(csaf);
        if (result == null) {
            return pm.makePersistent(csaf);
        }

        return result;
    }

    /**
     * Updates an existing CSAF source entity.
     *
     * @param source The CSAF source entity to update
     * @return the updated CSAF entity
     */
    @Override
    public @Nullable CsafSourceEntity updateCsafSource(CsafSourceEntity source) {
        LOGGER.debug("Updating within CsafQueryManager " + source.getId());
        try {
            final CsafSourceEntity existing = getObjectById(CsafSourceEntity.class, source.getId());
            applyIfChanged(existing, source, CsafSourceEntity::getName, existing::setName);
            applyIfChanged(existing, source, CsafSourceEntity::getUrl, existing::setUrl);
            applyIfChanged(existing, source, CsafSourceEntity::getContent, existing::setContent);
            applyIfChanged(existing, source, CsafSourceEntity::getLastFetched, existing::setLastFetched);
            applyIfChanged(existing, source, CsafSourceEntity::isEnabled, existing::setEnabled);
            applyIfChanged(existing, source, CsafSourceEntity::isAggregator, existing::setAggregator);
            applyIfChanged(existing, source, CsafSourceEntity::isDiscovery, existing::setDiscovery);
            applyIfChanged(existing, source, CsafSourceEntity::isSeen, existing::setSeen);
            return persist(existing);
        } catch (JDOObjectNotFoundException e) {
            return null;
        }
    }

    @Override
    public PaginatedResult getCsafDocuments() {
        final Query<CsafDocumentEntity> query = pm.newQuery(CsafDocumentEntity.class);
        if (orderBy == null) query.setOrdering("id desc");

        return execute(query);
    }

    /**
     * Retrieves a specific CSAF document by its publisher namespace and tracking ID, which makes it unique.
     *
     * @param publisherNamespace the publisher namespace
     * @param trackingID         the tracking ID
     * @return the CSAF document entity (or null if it does not exist)
     */
    public @Nullable CsafDocumentEntity getCsafDocumentByPublisherNamespaceAndTrackingID(String publisherNamespace, String trackingID) {
        final Query<CsafDocumentEntity> query = pm.newQuery(CsafDocumentEntity.class, "publisherNamespace == :publisherNamespace && trackingID == :trackingID");
        query.setRange(0, 1);
        return singleResult(query.execute(publisherNamespace, trackingID));
    }

    @Override
    public PaginatedResult searchCsafDocuments(String searchText, int pageSize, int pageNumber, String sortName, String sortOrder) {
        String totalSql = "SELECT COUNT(*) FROM public.\"CSAFDOCUMENTENTITY\" ";
        ArrayList<Object> totalQueryParams = new ArrayList<Object>();
        if (!searchText.isBlank()) {
            totalSql += "WHERE searchvector @@ websearch_to_tsquery(?) ";
            totalQueryParams.add(searchText);
        }
        var totalQuery = pm.newQuery("javax.jdo.query.SQL", totalSql);

        Object totalRawResult = (searchText.isBlank()) ? totalQuery.execute() : totalQuery.execute(searchText);
        ForwardQueryResult<Long> totalQueryResult = (ForwardQueryResult<Long>) totalRawResult;
        long total = totalQueryResult.getFirst();

        // Construct query
        StringBuilder docSql = new StringBuilder("SELECT \"ID\",\"NAME\",\"URL\",\"SEEN\",\"LASTFETCHED\",\"PUBLISHERNAMESPACE\",\"TRACKINGID\",\"TRACKINGVERSION\" FROM public.\"CSAFDOCUMENTENTITY\" ");
        ArrayList<Object> docParams = new ArrayList<>();
        if (!searchText.isBlank()) {
            docSql.append("WHERE searchvector @@ websearch_to_tsquery(?) ");
            docParams.add(searchText);
        }
        if (!sortName.isBlank() && ALLOWED_SORT_COLUMNS.containsKey(sortName) && !sortOrder.isBlank() && ALLOWED_SORT_ORDERS.containsKey(sortOrder)) {
            docSql.append("ORDER BY ");
            docSql.append(ALLOWED_SORT_COLUMNS.get(sortName));
            docSql.append(" ");
            docSql.append(ALLOWED_SORT_ORDERS.get(sortOrder));
            docSql.append(" ");
        } else {
            docSql.append("ORDER BY \"ID\" ASC ");
        }
        docSql.append("LIMIT ? OFFSET ? ");
        long offset = (long) (pageNumber - 1) * pageSize;
        docParams.add(pageSize);
        docParams.add(offset);

        var query = pm.newQuery("javax.jdo.query.SQL", docSql.toString());
        query.setParameters(docParams.toArray());
        query.setResultClass(CsafDocumentEntity.class);
        List<CsafDocumentEntity> results = query.executeList();

        PaginatedResult pr = new PaginatedResult();
        pr.setObjects(results);
        pr.setTotal(total);
        return pr;
    }

    /**
     * Updates an existing CSAF document entity.
     *
     * @param csaf The CSAF document entity to update
     * @return the updated CSAF entity
     */
    @Override
    public CsafDocumentEntity updateCsafDocument(CsafDocumentEntity csaf) {
        LOGGER.debug("Updating within CsafQueryManager " + csaf.getId());
        final CsafDocumentEntity existing = getCsafDocumentByPublisherNamespaceAndTrackingID(csaf.getPublisherNamespace(), csaf.getTrackingID());
        if (existing != null) {
            applyIfChanged(existing, csaf, CsafDocumentEntity::getName, existing::setName);
            applyIfChanged(existing, csaf, CsafDocumentEntity::getUrl, existing::setUrl);
            applyIfChanged(existing, csaf, CsafDocumentEntity::getContent, existing::setContent);
            applyIfChanged(existing, csaf, CsafDocumentEntity::isSeen, existing::setSeen);
            applyIfChanged(existing, csaf, CsafDocumentEntity::getPublisherNamespace, existing::setPublisherNamespace);
            applyIfChanged(existing, csaf, CsafDocumentEntity::getTrackingID, existing::setTrackingID);
            applyIfChanged(existing, csaf, CsafDocumentEntity::getTrackingVersion, existing::setTrackingVersion);
            applyIfChanged(existing, csaf, CsafDocumentEntity::getLastFetched, existing::setLastFetched);
            return existing;
        }

        return null;
    }

    @Override
    public boolean toggleCsafDocumentSeen(CsafDocumentEntity csafDocument) {
        csafDocument.setSeen(!csafDocument.isSeen());
        pm.makePersistent(csafDocument);
        return false;
    }

    private static final Map<String, String> ALLOWED_SORT_COLUMNS = Map.of(
            "id", "\"ID\"",
            "name", "\"NAME\"",
            "publisherNamespace", "\"PUBLISHERNAMESPACE\"",
            "trackingVersion", "\"TRACKINGVERSION\"",
            "lastFetched", "\"LASTFETCHED\"",
            "seen", "\"SEEN\""
    );
    private static final Map<String, String> ALLOWED_SORT_ORDERS = Map.of(
            "asc", "ASC",
            "desc", "DESC"
    );
}
