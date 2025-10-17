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
import org.dependencytrack.model.Advisory;

import javax.annotation.Nullable;
import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.dependencytrack.util.PersistenceUtil.applyIfChanged;

/**
 * JDO Query manager for {@link Advisory} records.
 *
 * @since 5.7.0
 */
public class AdvisoryQueryManager extends QueryManager implements IQueryManager {
    private static final Logger LOGGER = Logger.getLogger(AdvisoryQueryManager.class);

    /**
     * Constructs a new {@link AdvisoryQueryManager}.
     *
     * @param pm a PersistenceManager object
     */
    AdvisoryQueryManager(final PersistenceManager pm) {
        super(pm);
    }

    /**
     * Constructs a new {@link AdvisoryQueryManager}.
     *
     * @param pm      a PersistenceManager object
     * @param request an AlpineRequest object
     */
    AdvisoryQueryManager(final PersistenceManager pm, final AlpineRequest request) {
        super(pm, request);
    }

    /**
     * Synchronizes a {{@link Advisory}}. This method first checks if the record
     * already exists and updates it. If it does exist, it will create a new record.
     *
     * @param advisory The advisory to synchronize
     * @return an advisory entity
     */
    public Advisory synchronizeAdvisory(Advisory advisory) {
        Advisory result = updateAdvisory(advisory);
        if (result == null) {
            return pm.makePersistent(advisory);
        }

        return result;
    }

    /**
     * Retrieves a specific advisory by its publisher namespace and name, which makes it unique.
     *
     * @param publisher the publisher namespace
     * @param name         the name
     * @return the advisory entity (or null if it does not exist)
     */
    @Override
    public @Nullable Advisory getAdvisoryByPublisherAndName(String publisher, String name) {
        final Query<Advisory> query = pm.newQuery(Advisory.class, "publisher == :publisher && name == :name");
        query.setRange(0, 1);

        return singleResult(query.execute(publisher, name));
    }

    @Override
    public PaginatedResult getAllAdvisories(String format, String searchText, int pageSize, int pageNumber, String sortName, String sortOrder) {
        searchText = (searchText == null ? "" : searchText);
        String totalSql = "SELECT COUNT(*) FROM public.\"ADVISORY\" ";
        totalSql += "WHERE \"FORMAT\"=? ";
        if (!searchText.isBlank()) {
            totalSql += "AND searchvector @@ websearch_to_tsquery(?) ";
        }
        var totalQuery = pm.newQuery("javax.jdo.query.SQL", totalSql);

        Object totalRawResult = (searchText.isBlank()) ? totalQuery.execute(format) : totalQuery.execute(format, searchText);
        ForwardQueryResult<Long> totalQueryResult = (ForwardQueryResult<Long>) totalRawResult;
        long total = totalQueryResult.getFirst();

        // Construct query
        StringBuilder docSql = new StringBuilder("SELECT \"ID\",\"TITLE\",\"URL\",\"SEEN\",\"LASTFETCHED\",\"PUBLISHER\",\"NAME\",\"VERSION\" FROM public.\"ADVISORY\" ");
        ArrayList<Object> docParams = new ArrayList<>();
        docSql.append("WHERE \"FORMAT\"=? ");
        docParams.add(format);
        if (!searchText.isBlank()) {
            docSql.append("AND searchvector @@ websearch_to_tsquery(?) ");
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
        query.setResultClass(Advisory.class);
        List<Advisory> results = query.executeList();

        PaginatedResult pr = new PaginatedResult();
        pr.setObjects(results);
        pr.setTotal(total);
        return pr;
    }

    /**
     * Updates an existing advisory.
     *
     * @param advisory The advisory entity to update
     * @return the updated advisory entity
     */
    @Override
    public Advisory updateAdvisory(Advisory advisory) {
        final Advisory existing = getAdvisoryByPublisherAndName(advisory.getPublisher(), advisory.getName());
        if (existing != null) {
            applyIfChanged(existing, advisory, Advisory::getTitle, existing::setTitle);
            applyIfChanged(existing, advisory, Advisory::getUrl, existing::setUrl);
            applyIfChanged(existing, advisory, Advisory::getContent, existing::setContent);
            applyIfChanged(existing, advisory, Advisory::isSeen, existing::setSeen);
            applyIfChanged(existing, advisory, Advisory::getPublisher, existing::setPublisher);
            applyIfChanged(existing, advisory, Advisory::getName, existing::setName);
            applyIfChanged(existing, advisory, Advisory::getVersion, existing::setVersion);
            applyIfChanged(existing, advisory, Advisory::getFormat, existing::setFormat);
            applyIfChanged(existing, advisory, Advisory::getLastFetched, existing::setLastFetched);
            return existing;
        }

        return null;
    }

    @Override
    public void toggleAdvisorySeen(Advisory advisory) {
        advisory.setSeen(!advisory.isSeen());
        pm.makePersistent(advisory);
        return;
    }

    private static final Map<String, String> ALLOWED_SORT_COLUMNS = Map.of(
            "id", "\"ID\"",
            "name", "\"NAME\"",
            "publisherNamespace", "\"PUBLISHER\"",
            "trackingVersion", "\"VERSION\"",
            "lastFetched", "\"LASTFETCHED\"",
            "seen", "\"SEEN\""
    );
    private static final Map<String, String> ALLOWED_SORT_ORDERS = Map.of(
            "asc", "ASC",
            "desc", "DESC"
    );

}
