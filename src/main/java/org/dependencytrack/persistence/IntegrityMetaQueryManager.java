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
import alpine.resources.AlpineRequest;
import alpine.server.util.DbUtil;
import org.dependencytrack.model.FetchStatus;
import org.dependencytrack.model.IntegrityMetaComponent;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;

public class IntegrityMetaQueryManager extends QueryManager implements IQueryManager {

    private static final Logger LOGGER = Logger.getLogger(IntegrityMetaQueryManager.class);

    /**
     * Constructs a new QueryManager.
     * @param pm a PersistenceManager object
     */
    IntegrityMetaQueryManager(final PersistenceManager pm) {
        super(pm);
    }

    /**
     * Constructs a new QueryManager.
     * @param pm a PersistenceManager object
     * @param request an AlpineRequest object
     */
    IntegrityMetaQueryManager(final PersistenceManager pm, final AlpineRequest request) {
        super(pm, request);
    }

    /**
     * Returns a IntegrityMetaComponent object from the specified purl.
     *
     * @param purl           the Package URL string of the component
     * @return a IntegrityMetaComponent object, or null if not found
     */
    public IntegrityMetaComponent getIntegrityMetaComponent(String purl) {
        final Query<IntegrityMetaComponent> query = pm.newQuery(IntegrityMetaComponent.class, "purl == :purl");
        query.setParameters(purl);
        return query.executeUnique();
    }

    /**
     * Updates a IntegrityMetaComponent record.
     *
     * @param transientIntegrityMetaComponent the IntegrityMetaComponent object to synchronize
     * @return a synchronized IntegrityMetaComponent object
     */
    public synchronized IntegrityMetaComponent updateIntegrityMetaComponent(final IntegrityMetaComponent transientIntegrityMetaComponent) {
        final IntegrityMetaComponent integrityMeta = getIntegrityMetaComponent(transientIntegrityMetaComponent.getPurl());
        if (integrityMeta != null) {
            integrityMeta.setMd5(transientIntegrityMetaComponent.getMd5());
            integrityMeta.setSha1(transientIntegrityMetaComponent.getSha1());
            integrityMeta.setSha256(transientIntegrityMetaComponent.getSha256());
            integrityMeta.setSha512(transientIntegrityMetaComponent.getSha512());
            integrityMeta.setPublishedAt(transientIntegrityMetaComponent.getPublishedAt());
            integrityMeta.setStatus(transientIntegrityMetaComponent.getStatus());
            integrityMeta.setLastFetch(Date.from(Instant.now()));
            integrityMeta.setRepositoryUrl(transientIntegrityMetaComponent.getRepositoryUrl());
            return persist(integrityMeta);
        } else {
            LOGGER.debug("No record found in IntegrityMetaComponent for purl " + transientIntegrityMetaComponent.getPurl());
            return null;
        }
    }

    public IntegrityMetaComponent createIntegrityMetaComponent(IntegrityMetaComponent integrityMetaComponent) {
        return persist(integrityMetaComponent);
    }

    public void createIntegrityMetaHandlingConflict(IntegrityMetaComponent integrityMetaComponent) {
        final String createQuery = """
                    INSERT INTO "INTEGRITY_META_COMPONENT" ("PURL", "STATUS", "LAST_FETCH")
                    VALUES (?, ?, ?) 
                    ON CONFLICT DO NOTHING
                """;
        Connection connection = null;
        PreparedStatement preparedStatement = null;
        try {
            connection = (Connection) pm.getDataStoreConnection();
            preparedStatement = connection.prepareStatement(createQuery);
            preparedStatement.setString(1, integrityMetaComponent.getPurl().toString());
            preparedStatement.setString(2, integrityMetaComponent.getStatus().toString());
            preparedStatement.setTimestamp(3, new java.sql.Timestamp(integrityMetaComponent.getLastFetch().getTime()));
            preparedStatement.execute();
        } catch (Exception ex) {
            LOGGER.error("Error in creating integrity meta component", ex);
            throw new RuntimeException(ex);
        } finally {
            DbUtil.close(preparedStatement);
            DbUtil.close(connection);
        }
    }

    /**
     * Synchronizes IntegrityMetaComponent with purls from COMPONENT. This is part of initializer.
     */
    public synchronized void synchronizeIntegrityMetaComponent() {
        final String purlSyncQuery = """
                    INSERT INTO "INTEGRITY_META_COMPONENT" ("PURL")
                    SELECT DISTINCT "PURL"
                    FROM "COMPONENT"
                    WHERE "PURL" IS NOT NULL
                    ON CONFLICT DO NOTHING
                """;
        Connection connection = null;
        PreparedStatement preparedStatement = null;
        try {
            connection = (Connection) pm.getDataStoreConnection();
            preparedStatement = connection.prepareStatement(purlSyncQuery);
            var purlCount = preparedStatement.executeUpdate();
            LOGGER.info("Number of component purls synchronized for integrity check : " + purlCount);
        } catch (Exception ex) {
            LOGGER.error("Error in synchronizing component purls for integrity meta.", ex);
            throw new RuntimeException(ex);
        } finally {
            DbUtil.close(preparedStatement);
            DbUtil.close(connection);
        }
    }

    /**
     * Returns the count of records in IntegrityMetaComponent.
     *
     * @return the count of records
     */
    public long getIntegrityMetaComponentCount() {
        try (final Query<IntegrityMetaComponent> query = pm.newQuery(IntegrityMetaComponent.class)) {
            query.setResult("count(this)");
            return query.executeResultUnique(Long.class);
        } catch (Exception e) {
            LOGGER.error("Error in getting count of integrity meta.", e);
            throw new RuntimeException(e);
        }
    }

    /**
     * Returns the list of purls in IntegrityMetaComponent which are not yet processed.
     *
     * @return the list of purls
     */
    public List<IntegrityMetaComponent> fetchNextPurlsPage(long offset) {
        try (final Query<IntegrityMetaComponent> query =
                     pm.newQuery(IntegrityMetaComponent.class, "status == null || (status == :inProgress && lastFetch < :latest)")) {
            query.setParameters(FetchStatus.IN_PROGRESS, Date.from(Instant.now().minus(1, ChronoUnit.HOURS)));
            query.setRange(offset, offset + 5000);
            query.setResult("id, purl");
            return List.copyOf(query.executeResultList(IntegrityMetaComponent.class));
        } catch (Exception e) {
            LOGGER.error("Error in getting purls from integrity meta.", e);
            throw new RuntimeException(e);
        }
    }

    /**
     * Batch updates IntegrityMetaComponent records
     */
    public void batchUpdateIntegrityMetaComponent(List<IntegrityMetaComponent> purls) {
        final String updateQuery = """
                UPDATE "INTEGRITY_META_COMPONENT"
                SET "LAST_FETCH" = ?, "STATUS" = ?
                WHERE "ID" = ? AND ("STATUS" IS NULL OR "STATUS" = 'IN_PROGRESS')
                """;
        Connection connection = null;
        PreparedStatement preparedStatement = null;
        try {
            connection = (Connection) pm.getDataStoreConnection();
            preparedStatement = connection.prepareStatement(updateQuery);
            for (var purlRecord : purls) {
                preparedStatement.setTimestamp(1, new Timestamp(Date.from(Instant.now()).getTime()));
                preparedStatement.setString(2, FetchStatus.IN_PROGRESS.toString());
                preparedStatement.setLong(3, purlRecord.getId());
                preparedStatement.addBatch();
            }
            preparedStatement.executeBatch();
        } catch (Exception ex) {
            LOGGER.error("Error in batch updating integrity meta.", ex);
            throw new RuntimeException(ex);
        } finally {
            DbUtil.close(preparedStatement);
            DbUtil.close(connection);
        }
    }
}
