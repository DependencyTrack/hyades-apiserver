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
package org.dependencytrack.persistence.jdbi;

import org.datanucleus.store.types.wrappers.Date;
import org.dependencytrack.model.ComponentMetaInformation;
import org.dependencytrack.model.IntegrityMatchStatus;
import org.jdbi.v3.core.mapper.reflect.ConstructorMapper;
import org.jdbi.v3.core.statement.Query;
import org.jdbi.v3.sqlobject.SqlObject;
import org.jdbi.v3.sqlobject.statement.SqlUpdate;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * @since 5.6.0
 */
public interface ComponentMetaDao extends SqlObject {

    record ComponentMetaInfoRecord(
            UUID componentUuid,
            String purl,
            Instant lastFetch,
            Instant publishedAt,
            IntegrityMatchStatus integrityCheckStatus,
            String repositoryUrl) {
    }

    default Map<UUID, ComponentMetaInformation> getComponentMetaInfo(final Collection<UUID> uuids) {
        final Query query = getHandle().createQuery("""
                SELECT c."UUID" AS component_uuid
                     , c."PURL"
                     , imc."LAST_FETCH"
                     , imc."PUBLISHED_AT"
                     , ia."INTEGRITY_CHECK_STATUS"
                     , imc."REPOSITORY_URL"
                  FROM "COMPONENT" AS c
                 INNER JOIN "INTEGRITY_META_COMPONENT" AS imc
                    ON c."PURL" = imc."PURL"
                  LEFT JOIN "INTEGRITY_ANALYSIS" AS ia
                    ON ia."COMPONENT_ID" = c."ID"
                 WHERE c."UUID" = ANY(:uuids)
                """);

        return query
                .bindArray("uuids", UUID.class, uuids)
                .map(ConstructorMapper.of(ComponentMetaInfoRecord.class))
                .stream()
                .collect(Collectors.toMap(
                        ComponentMetaInfoRecord::componentUuid,
                        record -> new ComponentMetaInformation(
                                record.publishedAt() != null ? Date.from(record.publishedAt()) : null,
                                record.integrityCheckStatus(),
                                record.lastFetch() != null ? Date.from(record.lastFetch()) : null,
                                record.repositoryUrl())));
    }

    default ComponentMetaInformation getComponentMetaInfo(final UUID uuid) {
        final Map<UUID, ComponentMetaInformation> metaByUuid = getComponentMetaInfo(List.of(uuid));
        return metaByUuid.get(uuid);
    }

    @SqlUpdate("""
            DELETE
              FROM "INTEGRITY_META_COMPONENT"
             WHERE NOT EXISTS(
               SELECT 1
                 FROM "COMPONENT"
                WHERE "COMPONENT"."PURL" = "INTEGRITY_META_COMPONENT"."PURL")
            """)
    int deleteOrphanIntegrityMetaComponents();

    // TODO: Do a NOT EXISTS query against the COMPONENT table instead.
    //  Requires https://github.com/DependencyTrack/hyades/issues/1465.
    @SqlUpdate("""
            DELETE
              FROM "REPOSITORY_META_COMPONENT"
             WHERE NOW() - "LAST_CHECK" > INTERVAL '30' DAY
            """)
    int deleteOrphanRepositoryMetaComponents();

}
