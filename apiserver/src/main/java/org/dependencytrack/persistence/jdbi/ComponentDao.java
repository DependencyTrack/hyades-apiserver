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

import org.dependencytrack.common.pagination.Page;
import org.dependencytrack.common.pagination.PageToken;
import org.dependencytrack.common.pagination.PageTokenEncoder;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ComponentIdentity;
import org.dependencytrack.model.ComponentOccurrence;
import org.dependencytrack.model.DependencyMetrics;
import org.dependencytrack.model.License;
import org.dependencytrack.model.Project;
import org.jdbi.v3.core.mapper.RowMapper;
import org.jdbi.v3.core.mapper.reflect.BeanMapper;
import org.jdbi.v3.core.statement.StatementContext;
import org.jdbi.v3.sqlobject.SqlObject;
import org.jdbi.v3.sqlobject.config.RegisterBeanMapper;
import org.jdbi.v3.sqlobject.config.RegisterRowMapper;
import org.jdbi.v3.sqlobject.customizer.Bind;
import org.jdbi.v3.sqlobject.customizer.DefineNamedBindings;
import org.jdbi.v3.sqlobject.statement.SqlQuery;
import org.jdbi.v3.sqlobject.statement.SqlUpdate;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;
import static org.dependencytrack.persistence.jdbi.mapping.RowMapperUtil.hasColumn;
import static org.dependencytrack.persistence.jdbi.mapping.RowMapperUtil.maybeSet;

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

    default Page<Component> listProjectComponents(
            final long projectId,
            final Boolean onlyOutdated,
            final Boolean onlyDirect,
            final int limit,
            final String pageToken) {
        final PageTokenEncoder pageTokenEncoder =
                getHandle().getConfig(PaginationConfig.class).getPageTokenEncoder();
        final var decodedPageToken = pageTokenEncoder.decode(pageToken, ListComponentPageToken.class);

        final List<Component> rows = listProjectComponents(projectId, limit + 1, onlyOutdated, onlyDirect,
                decodedPageToken != null ? decodedPageToken.lastName() : null,
                decodedPageToken != null ? decodedPageToken.lastVersion() : null,
                decodedPageToken != null ? decodedPageToken.lastId() : null);

        final List<Component> resultRows = rows.size() > 1
                ? rows.subList(0, Math.min(rows.size(), limit))
                : rows;

        final ListComponentPageToken nextPageToken = rows.size() > limit
                ? new ListComponentPageToken(resultRows.getLast().getName(), resultRows.getLast().getVersion(), resultRows.getLast().getId())
                : null;

        return new Page<>(resultRows, pageTokenEncoder.encode(nextPageToken));
    }

    record ListComponentPageToken(String lastName, String lastVersion, Long lastId) implements PageToken {
    }

    @SqlQuery(/* language=InjectedFreeMarker */ """
            <#-- @ftlvariable name="onlyOutdated" type="Boolean" -->
            <#-- @ftlvariable name="onlyDirect" type="Boolean" -->
            <#-- @ftlvariable name="apiProjectAclCondition" type="String" -->
            SELECT "C"."ID",
                        "C"."NAME",
                        "C"."BLAKE2B_256",
                        "C"."BLAKE2B_384",
                        "C"."BLAKE2B_512",
                        "C"."BLAKE3",
                        "C"."CLASSIFIER",
                        "C"."COPYRIGHT",
                        "C"."CPE",
                        "C"."PURL" AS "componentPurl",
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
                <#if lastName && lastVersion && lastId>
                    AND ("C"."NAME" > :lastName
                            OR ("C"."NAME" = :lastName AND "C"."VERSION" < :lastVersion)
                            OR ("C"."NAME" = :lastName AND "C"."VERSION" = :lastVersion AND "C"."ID" > :lastId))
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
    @RegisterRowMapper(ComponentListRowMapper.class)
    List<Component> listProjectComponents(
            @Bind long projectId,
            @Bind int limit,
            @Bind Boolean onlyOutdated,
            @Bind Boolean onlyDirect,
            @Bind String lastName,
            @Bind String lastVersion,
            @Bind Long lastId
    );

    default Page<Component> listComponents(
            final long projectId,
            final Boolean includeMetrics,
            final ComponentIdentity identity,
            final int limit,
            final String pageToken) {
        final PageTokenEncoder pageTokenEncoder =
                getHandle().getConfig(PaginationConfig.class).getPageTokenEncoder();
        final var decodedPageToken = pageTokenEncoder.decode(pageToken, ListComponentPageToken.class);

        final List<Component> rows;
        String componentGroup = null;
        String componentName = null;
        String componentVersion = null;
        String componentPurl = null;
        String componentCpe = null;
        String componentSwidTagId = null;

        if (identity.getGroup() != null || identity.getName() != null || identity.getVersion() != null) {
            if (identity.getGroup() != null) {
                componentGroup = identity.getGroup().toLowerCase();
            }
            if (identity.getName() != null) {
                componentName = identity.getName().toLowerCase();
            }
            if (identity.getVersion() != null) {
                componentVersion = identity.getVersion().toLowerCase();
            }
        } else if (identity.getPurl() != null) {
            componentPurl = identity.getPurl().canonicalize().toLowerCase();
        } else if (identity.getCpe() != null) {
            componentCpe = identity.getCpe().toLowerCase();
        } else if (identity.getSwidTagId() != null) {
            componentSwidTagId = identity.getSwidTagId().toLowerCase();
        }

        rows = listComponents(projectId, limit + 1,
                componentGroup, componentName, componentVersion, componentPurl, componentCpe, componentSwidTagId,
                decodedPageToken != null ? decodedPageToken.lastName() : null,
                decodedPageToken != null ? decodedPageToken.lastVersion() : null,
                decodedPageToken != null ? decodedPageToken.lastId() : null);

        final List<Component> resultRows = rows.size() > 1
                ? rows.subList(0, Math.min(rows.size(), limit))
                : rows;

        final ListComponentPageToken nextPageToken = rows.size() > limit
                ? new ListComponentPageToken(resultRows.getLast().getName(), resultRows.getLast().getVersion(), resultRows.getLast().getId())
                : null;

        if (includeMetrics) {
            final Map<Long, Component> componentById = resultRows.stream()
                    .collect(Collectors.toMap(Component::getId, Function.identity()));
            final List<DependencyMetrics> metricsList = withJdbiHandle(
                    handle -> handle.attach(MetricsDao.class).getMostRecentDependencyMetrics(componentById.keySet()));
            for (final DependencyMetrics metrics : metricsList) {
                final var component = componentById.get(metrics.getComponentId());
                if (component != null) {
                    component.setMetrics(metrics);
                }
            }
        }

        return new Page<>(resultRows, pageTokenEncoder.encode(nextPageToken));
    }

    @SqlQuery(/* language=InjectedFreeMarker */ """
            <#-- @ftlvariable name="apiProjectAclCondition" type="String" -->
            SELECT "C"."ID",
                        "C"."NAME",
                        "C"."BLAKE2B_256",
                        "C"."BLAKE2B_384",
                        "C"."BLAKE2B_512",
                        "C"."BLAKE3",
                        "C"."CLASSIFIER",
                        "C"."COPYRIGHT",
                        "C"."CPE",
                        "C"."PURL" AS "componentPurl",
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
                        "C"."SWIDTAGID",
                        "C"."UUID",
                        "C"."VERSION",
                        "PROJECT"."NAME" AS "projectName"
                FROM "COMPONENT" "C"
                INNER JOIN "PROJECT" ON "C"."PROJECT_ID" = "PROJECT"."ID"
                WHERE ${apiProjectAclCondition}
                AND "C"."PROJECT_ID" = :projectId
                <#if lastName && lastVersion && lastId>
                    AND ("C"."NAME" > :lastName
                            OR ("C"."NAME" = :lastName AND "C"."VERSION" < :lastVersion)
                            OR ("C"."NAME" = :lastName AND "C"."VERSION" = :lastVersion AND "C"."ID" > :lastId))
                </#if>
                ORDER BY "NAME" ASC, "VERSION" DESC, "ID" ASC
                LIMIT :limit
            """)
    @DefineNamedBindings
    @DefineApiProjectAclCondition(projectIdColumn = "\"PROJECT_ID\"")
    @RegisterRowMapper(ComponentListRowMapper.class)
    List<Component> listComponents(
            @Bind long projectId,
            @Bind int limit,
            @Bind String componentGroup,
            @Bind String componentName,
            @Bind String componentVersion,
            @Bind String componentPurl,
            @Bind String componentCpe,
            @Bind String componentSwidTagId,
            @Bind String lastName,
            @Bind String lastVersion,
            @Bind Long lastId
    );

    class ComponentListRowMapper implements RowMapper<Component> {

        private final RowMapper<Component> componentRowMapper = BeanMapper.of(Component.class);

        @Override
        public Component map(final ResultSet rs, final StatementContext ctx) throws SQLException {
            final Component component = componentRowMapper.map(rs, ctx);
            if (hasColumn(rs, "projectName") && rs.getString("projectName") != null) {
                final var project = new Project();
                project.setName(rs.getString("projectName"));
                component.setProject(project);
            }
            maybeSet(rs, "componentPurl", ResultSet::getString, component::setPurl);
            if (hasColumn(rs, "licenseUuid") && rs.getString("licenseUuid") != null) {
                final var license = new License();
                license.setUuid(UUID.fromString(rs.getString("licenseUuid")));
                maybeSet(rs, "licenseId", ResultSet::getString, license::setLicenseId);
                maybeSet(rs, "licenseName", ResultSet::getString, license::setName);
                maybeSet(rs, "isCustomLicense", ResultSet::getBoolean, license::setCustomLicense);
                maybeSet(rs, "isFsfLibre", ResultSet::getBoolean, license::setFsfLibre);
                maybeSet(rs, "isOsiApproved", ResultSet::getBoolean, license::setOsiApproved);
                component.setResolvedLicense(license);
            }
            if (hasColumn(rs, "occurrenceCount")) {
                maybeSet(rs, "occurrenceCount", ResultSet::getLong, component::setOccurrenceCount);
            }
            return component;
        }
    }
}
