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

import org.dependencytrack.model.Component;
import org.dependencytrack.model.ComponentOccurrence;
import org.dependencytrack.model.License;
import org.dependencytrack.persistence.jdbi.mapping.ExternalReferenceMapper;
import org.dependencytrack.persistence.jdbi.mapping.OrganizationalContactMapper;
import org.dependencytrack.persistence.jdbi.mapping.OrganizationalEntityMapper;
import org.dependencytrack.persistence.pagination.Page;
import org.jdbi.v3.core.mapper.RowMapper;
import org.jdbi.v3.core.mapper.reflect.BeanMapper;
import org.jdbi.v3.core.statement.StatementContext;
import org.jdbi.v3.sqlobject.SqlObject;
import org.jdbi.v3.sqlobject.config.RegisterBeanMapper;
import org.jdbi.v3.sqlobject.config.RegisterColumnMapper;
import org.jdbi.v3.sqlobject.config.RegisterRowMapper;
import org.jdbi.v3.sqlobject.customizer.Bind;
import org.jdbi.v3.sqlobject.customizer.DefineNamedBindings;
import org.jdbi.v3.sqlobject.statement.SqlQuery;
import org.jdbi.v3.sqlobject.statement.SqlUpdate;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import java.util.UUID;

import static org.dependencytrack.persistence.jdbi.mapping.RowMapperUtil.maybeSet;
import static org.dependencytrack.persistence.pagination.PageUtil.decodePageToken;
import static org.dependencytrack.persistence.pagination.PageUtil.encodePageToken;

public interface ComponentDao extends SqlObject {

    @SqlUpdate("""
            DELETE
              FROM "COMPONENT"
             WHERE "UUID" = :componentUuid
            """)
    int deleteComponent(@Bind final UUID componentUuid);

    @SqlQuery(/* language=InjectedFreeMarker */ """
            <#-- @ftlvariable name="apiProjectAclCondition" type="String" -->
            SELECT ${apiProjectAclCondition}
              FROM "COMPONENT"
             WHERE "UUID" = :componentUuid
            """)
    @DefineApiProjectAclCondition(projectIdColumn = "\"PROJECT_ID\"")
    Boolean isAccessible(@Bind UUID componentUuid);

    @SqlQuery(/* language=InjectedFreeMarker */ """
            <#-- @ftlvariable name="apiFilterParameter" type="String" -->
            <#-- @ftlvariable name="apiOffsetLimitClause" type="String" -->
            SELECT "COMPONENT_OCCURRENCE"."ID"
                 , "LOCATION"
                 , "LINE"
                 , "OFFSET"
                 , "SYMBOL"
                 , "CREATED_AT"
                 , COUNT(*) OVER() AS "TOTAL_COUNT"
              FROM "COMPONENT"
             INNER JOIN "COMPONENT_OCCURRENCE"
                ON "COMPONENT_OCCURRENCE"."COMPONENT_ID" = "COMPONENT"."ID"
             WHERE "COMPONENT"."UUID" = :componentUuid
            <#if apiFilterParameter??>
               AND LOWER("LOCATION") LIKE ('%' || LOWER(${apiFilterParameter}) || '%')
            </#if>
            ORDER BY "LOCATION", "COMPONENT_OCCURRENCE"."ID"
            ${apiOffsetLimitClause!}
            """)
    @RegisterBeanMapper(ComponentOccurrence.class)
    List<ComponentOccurrence> getOccurrences(@Bind UUID componentUuid);

    @SqlQuery("""
            SELECT "ID" FROM "COMPONENT" WHERE "UUID" = :componentUuid
            """)
    Long getComponentId(@Bind UUID componentUuid);

    default Page<Component> getComponentsForProject(final long projectId, final Boolean onlyOutdated,
                                                    final Boolean onlyDirect, final int limit, final String pageToken) {
        final var decodedPageToken = decodePageToken(getHandle(), pageToken, ListComponentPageToken.class);

        final List<Component> rows = getComponentsForProject(projectId, limit + 1, onlyOutdated, onlyDirect,
                decodedPageToken != null ? decodedPageToken.lastName() : null,
                decodedPageToken != null ? decodedPageToken.lastVersion() : null);

        final List<Component> resultRows = rows.size() > 1
                ? rows.subList(0, Math.min(rows.size(), limit))
                : rows;

        final ListComponentPageToken nextPageToken = rows.size() > limit
                ? new ListComponentPageToken(resultRows.getLast().getName(), resultRows.getLast().getVersion())
                : null;

        return new Page<>(resultRows, encodePageToken(getHandle(), nextPageToken));
    }

    record ListComponentPageToken(String lastName, String lastVersion) {
    }

    @SqlQuery(/* language=InjectedFreeMarker */ """
            <#-- @ftlvariable name="onlyOutdated" type="Boolean" -->
            <#-- @ftlvariable name="onlyDirect" type="Boolean" -->
            <#-- @ftlvariable name="apiProjectAclCondition" type="String" -->
            SELECT "C"."ID",
                        "C"."NAME",
                        "C"."AUTHORS",
                        "C"."BLAKE2B_256",
                        "C"."BLAKE2B_384",
                        "C"."BLAKE2B_512",
                        "C"."BLAKE3",
                        "C"."CLASSIFIER",
                        "C"."COPYRIGHT",
                        "C"."CPE",
                        "C"."PUBLISHER",
                        "C"."PURL" AS "componentPurl",
                        "C"."PURLCOORDINATES",
                        "C"."DESCRIPTION",
                        "C"."DIRECT_DEPENDENCIES" AS "directDependencies",
                        "C"."EXTENSION",
                        "C"."EXTERNAL_REFERENCES" AS "externalReferences",
                        "C"."FILENAME",
                        "C"."GROUP",
                        "C"."INTERNAL",
                        "C"."LAST_RISKSCORE" AS "lastInheritedRiskScore",
                        "C"."LICENSE" AS "componentLicenseName",
                        "C"."LICENSE_EXPRESSION" AS "licenseExpression",
                        "C"."LICENSE_URL" AS "licenseUrl",
                        "C"."TEXT",
                        "C"."MD5",
                        "C"."SHA1",
                        "C"."SHA_256" AS "sha256",
                        "C"."SHA_384" AS "sha384",
                        "C"."SHA_512" AS "sha512",
                        "C"."SHA3_256",
                        "C"."SHA3_384",
                        "C"."SHA3_512",
                        "C"."SUPPLIER",
                        "C"."SWIDTAGID",
                        "C"."UUID",
                        "C"."VERSION",
                        "L"."ISCUSTOMLICENSE",
                        "L"."FSFLIBRE" AS "isFsfLibre",
                        "L"."LICENSEID",
                        "L"."ISOSIAPPROVED",
                        "L"."UUID" AS "licenseUuid",
                        "L"."NAME" AS "licenseName",
                        (SELECT COUNT(*) FROM "COMPONENT_OCCURRENCE" WHERE "COMPONENT_ID" = "C"."ID") AS "occurrenceCount"
                FROM "COMPONENT" "C"
                INNER JOIN "PROJECT" ON "C"."PROJECT_ID" = "PROJECT"."ID"
                LEFT OUTER JOIN "LICENSE" "L" ON "C"."LICENSE_ID" = "L"."ID"
                WHERE ${apiProjectAclCondition}
                AND "C"."PROJECT_ID" = :projectId
                <#if lastName && lastVersion>
                   AND ("C"."NAME", "C"."VERSION") < (:lastName, :lastVersion)
                </#if>
                <#if onlyOutdated && onlyOutdated == true>
                    AND NOT (NOT EXISTS (
                        SELECT "R"."ID"
                        FROM "REPOSITORY_META_COMPONENT" "R" WHERE "R"."NAME" = "C"."NAME"
                        AND ("R"."NAMESPACE" = "C"."GROUP" OR "R"."NAMESPACE" IS NULL OR "C"."GROUP" IS NULL)
                        AND "R"."LATEST_VERSION" <> "C"."VERSION"
                        AND "C"."PURL" LIKE (('pkg:' || LOWER("R"."REPOSITORY_TYPE")) || '/%') ESCAPE E'\\\\'))
                </#if>
                <#if onlyDirect && onlyDirect == true>
                    AND "PROJECT"."DIRECT_DEPENDENCIES" @> JSONB_BUILD_ARRAY(JSONB_BUILD_OBJECT('uuid', "C"."UUID"))
                </#if>
                ORDER BY "NAME" ASC, "VERSION" DESC, "ID" ASC
                LIMIT :limit
            """)
    @DefineNamedBindings
    @DefineApiProjectAclCondition(projectIdColumn = "\"PROJECT_ID\"")
    @RegisterColumnMapper(ExternalReferenceMapper.class)
    @RegisterColumnMapper(OrganizationalContactMapper.class)
    @RegisterColumnMapper(OrganizationalEntityMapper.class)
    @RegisterRowMapper(ComponentListRowMapper.class)
    List<Component> getComponentsForProject(
            @Bind long projectId,
            @Bind int limit,
            @Bind Boolean onlyOutdated,
            @Bind Boolean onlyDirect,
            @Bind String lastName,
            @Bind String lastVersion
    );

    class ComponentListRowMapper implements RowMapper<Component> {

        private final RowMapper<Component> componentRowMapper = BeanMapper.of(Component.class);

        @Override
        public Component map(final ResultSet rs, final StatementContext ctx) throws SQLException {
            final Component component = componentRowMapper.map(rs, ctx);
            maybeSet(rs, "componentPurl", ResultSet::getString, component::setPurl);
            if (rs.getString("licenseUuid") != null) {
                final var license = new License();
                license.setUuid(UUID.fromString(rs.getString("licenseUuid")));
                maybeSet(rs, "licenseId", ResultSet::getString, license::setLicenseId);
                maybeSet(rs, "licenseName", ResultSet::getString, license::setName);
                maybeSet(rs, "isCustomLicense", ResultSet::getBoolean, license::setCustomLicense);
                maybeSet(rs, "isFsfLibre", ResultSet::getBoolean, license::setFsfLibre);
                maybeSet(rs, "isOsiApproved", ResultSet::getBoolean, license::setOsiApproved);
                component.setResolvedLicense(license);
            }
            maybeSet(rs, "occurrenceCount", ResultSet::getLong, component::setOccurrenceCount);
            return component;
        }
    }
}
