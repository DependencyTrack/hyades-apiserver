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
package org.dependencytrack.policy.cel.persistence;

import alpine.common.logging.Logger;
import com.google.api.expr.v1alpha1.Type;
import org.apache.commons.collections4.MultiValuedMap;
import org.dependencytrack.policy.cel.mapping.ComponentProjection;
import org.dependencytrack.policy.cel.mapping.ProjectProjection;
import org.dependencytrack.policy.cel.mapping.ProjectPropertyProjection;
import org.dependencytrack.policy.cel.mapping.VulnerabilityProjection;
import org.dependencytrack.proto.policy.v1.Component;
import org.dependencytrack.proto.policy.v1.Project;
import org.dependencytrack.proto.policy.v1.Vulnerability;
import org.jdbi.v3.sqlobject.config.KeyColumn;
import org.jdbi.v3.sqlobject.config.RegisterRowMapper;
import org.jdbi.v3.sqlobject.customizer.Bind;
import org.jdbi.v3.sqlobject.customizer.Define;
import org.jdbi.v3.sqlobject.statement.SqlQuery;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.stream.Collectors;

import static org.dependencytrack.policy.cel.definition.CelPolicyTypes.TYPE_COMPONENT;
import static org.dependencytrack.policy.cel.definition.CelPolicyTypes.TYPE_PROJECT;
import static org.dependencytrack.policy.cel.definition.CelPolicyTypes.TYPE_PROJECT_METADATA;
import static org.dependencytrack.policy.cel.definition.CelPolicyTypes.TYPE_PROJECT_PROPERTY;
import static org.dependencytrack.policy.cel.definition.CelPolicyTypes.TYPE_VULNERABILITY;
import static org.dependencytrack.policy.cel.mapping.FieldMappingUtil.getFieldMappings;

public interface CelPolicyDao {

    Logger LOGGER = Logger.getLogger(CelPolicyDao.class);

    @SqlQuery("""
            SELECT ${fetchColumns?join(", ")}
              FROM "PROJECT" AS p
            <#if fetchColumns?filter(col -> col?contains("\\"metadata_tools\\""))?size gt 0>
             INNER JOIN "PROJECT_METADATA" AS pm
                ON pm."PROJECT_ID" = p."ID"
            </#if>
            <#if fetchColumns?filter(col -> col?contains("\\"bom_generated\\""))?size gt 0>
             INNER JOIN "BOM" AS b
                ON b."PROJECT_ID" = p."ID"
            </#if>
            <#if fetchPropertyColumns?size gt 0>
              LEFT JOIN LATERAL (
                SELECT CAST(JSONB_AGG(DISTINCT JSONB_BUILD_OBJECT(${fetchPropertyColumns?join(", ")})) AS TEXT) AS "properties"
                  FROM "PROJECT_PROPERTY" AS pp
                 WHERE pp."PROJECT_ID" = p."ID"
              ) AS "properties" ON TRUE
            </#if>
            <#if fetchColumns?seq_contains("\\"tags\\"")>
              LEFT JOIN LATERAL (
                SELECT ARRAY_AGG(DISTINCT t."NAME") AS "tags"
                  FROM "TAG" AS t
                 INNER JOIN "PROJECTS_TAGS" AS pt
                    ON pt."TAG_ID" = t."ID"
                 WHERE pt."PROJECT_ID" = p."ID"
              ) AS "tags" ON TRUE
            </#if>
             WHERE p."ID" = :id
            """)
    @RegisterRowMapper(CelPolicyProjectRowMapper.class)
    Project getProject(
            @Define List<String> fetchColumns,
            @Define List<String> fetchPropertyColumns,
            @Bind long id);

    @SqlQuery("""
            SELECT c."ID" AS db_id
            <#if fetchColumns?size gt 0>
                 , ${fetchColumns?join(", ")}
            </#if>
              FROM "COMPONENT" AS c
            <#if fetchColumns?seq_contains("\\"published_at\\"")>
              LEFT JOIN LATERAL (
                SELECT imc."PUBLISHED_AT" AS "published_at"
                  FROM "INTEGRITY_META_COMPONENT" AS imc
                 WHERE imc."PURL" = c."PURL"
              ) AS "integrityMeta" ON TRUE
            </#if>
            <#if fetchColumns?seq_contains("\\"latest_version\\"")>
              LEFT JOIN LATERAL (
                SELECT rmc."LATEST_VERSION" AS "latest_version"
                  FROM "REPOSITORY_META_COMPONENT" AS rmc
                 WHERE rmc."NAME" = c."NAME"
              ) AS "repoMeta" ON TRUE
            </#if>
             WHERE c."ID" = ANY(:ids)
            """)
    @KeyColumn("db_id")
    @RegisterRowMapper(CelPolicyComponentRowMapper.class)
    Map<Long, Component> getComponents(@Define List<String> fetchColumns, @Bind Collection<Long> ids);

    @SqlQuery("""
            SELECT v."ID" AS db_id
            <#if fetchColumns?size gt 0>
                 , ${fetchColumns?join(", ")}
            </#if>
              FROM "VULNERABILITY" AS v
            <#if fetchColumns?seq_contains("e.\\"SCORE\\" AS \\"epss_score\\"") || fetchColumns?seq_contains("e.\\"PERCENTILE\\" AS \\"epss_percentile\\"")>
              LEFT JOIN "EPSS" AS e
                ON v."VULNID" = e."CVE"
            </#if>
             WHERE v."ID" = ANY(:ids)
            """)
    @KeyColumn("db_id")
    @RegisterRowMapper(CelPolicyVulnerabilityRowMapper.class)
    Map<Long, Vulnerability> getVulnerabilities(@Define List<String> fetchColumns, @Bind Collection<Long> ids);

    default Project loadRequiredFields(long projectId, final MultiValuedMap<Type, String> requirements) {
        final Collection<String> projectRequirements = requirements.get(TYPE_PROJECT);
        if (projectRequirements == null || projectRequirements.isEmpty()) {
            return Project.getDefaultInstance();
        }

        final List<String> sqlSelectColumns = getFieldMappings(ProjectProjection.class).stream()
                .filter(fieldMapping -> projectRequirements.contains(fieldMapping.protoFieldName()))
                .map(fieldMapping -> "p.\"%s\" AS \"%s\"".formatted(fieldMapping.sqlColumnName(), fieldMapping.protoFieldName()))
                .collect(Collectors.toList());

        if (projectRequirements.contains("metadata")
            && requirements.containsKey(TYPE_PROJECT_METADATA)) {
            if (requirements.get(TYPE_PROJECT_METADATA).contains("tools")) {
                sqlSelectColumns.add("pm.\"TOOLS\" AS \"metadata_tools\"");
            }
            if (requirements.get(TYPE_PROJECT_METADATA).contains("bom_generated")) {
                sqlSelectColumns.add("b.\"GENERATED\" AS \"bom_generated\"");
            }
        }

        if (projectRequirements.contains("is_active")) {
            sqlSelectColumns.add("p.\"INACTIVE_SINCE\" AS \"inactive_since\"");
        }

        final var sqlPropertySelectColumns = new ArrayList<String>();
        if (projectRequirements.contains("properties") && requirements.containsKey(TYPE_PROJECT_PROPERTY)) {
            sqlSelectColumns.add("\"properties\"");

            getFieldMappings(ProjectPropertyProjection.class).stream()
                    .filter(mapping -> requirements.get(TYPE_PROJECT_PROPERTY).contains(mapping.protoFieldName()))
                    .map(mapping -> "'%s', pp.\"%s\"".formatted(mapping.protoFieldName(), mapping.sqlColumnName()))
                    .forEach(sqlPropertySelectColumns::add);
        }
        if (projectRequirements.contains("tags")) {
            sqlSelectColumns.add("\"tags\"");
        }

        final Project fetchedProject = getProject(sqlSelectColumns, sqlPropertySelectColumns, projectId);
        if (fetchedProject == null) {
            throw new NoSuchElementException();
        }

        return fetchedProject;
    }

    default Map<Long, Component> loadRequiredComponentFields(
            Collection<Long> componentIds,
            MultiValuedMap<Type, String> requirements) {
        if (componentIds.isEmpty()) {
            return Map.of();
        }

        final Collection<String> componentRequirements = requirements.get(TYPE_COMPONENT);
        if (componentRequirements == null || componentRequirements.isEmpty()) {
            final var result = new HashMap<Long, Component>();
            for (long componentId : componentIds) {
                result.put(componentId, Component.getDefaultInstance());
            }
            return result;
        }

        final List<String> sqlSelectColumns = getFieldMappings(ComponentProjection.class).stream()
                .filter(fieldMapping -> componentRequirements.contains(fieldMapping.protoFieldName()))
                .map(fieldMapping -> "c.\"%s\" AS \"%s\"".formatted(fieldMapping.sqlColumnName(), fieldMapping.protoFieldName()))
                .collect(Collectors.toList());

        if (componentRequirements.contains("latest_version")) {
            sqlSelectColumns.add("\"latest_version\"");
        }
        if (componentRequirements.contains("published_at")) {
            sqlSelectColumns.add("\"published_at\"");
        }

        return getComponents(sqlSelectColumns, componentIds);
    }

    default Map<Long, Vulnerability> loadRequiredVulnerabilityFields(
            Collection<Long> vulnIds,
            MultiValuedMap<Type, String> requirements) {
        if (vulnIds.isEmpty()) {
            return Map.of();
        }

        final Collection<String> vulnRequirements = requirements.get(TYPE_VULNERABILITY);
        if (vulnRequirements == null || vulnRequirements.isEmpty()) {
            final var result = new HashMap<Long, Vulnerability>();
            for (long vulnId : vulnIds) {
                result.put(vulnId, Vulnerability.getDefaultInstance());
            }
            return result;
        }

        final List<String> sqlSelectColumns = getFieldMappings(VulnerabilityProjection.class).stream()
                .filter(fieldMapping -> vulnRequirements.contains(fieldMapping.protoFieldName()))
                .map(fieldMapping -> {
                    if ("cwes".equals(fieldMapping.protoFieldName())) {
                        return "STRING_TO_ARRAY(v.\"%s\", ',') AS \"%s\""
                                .formatted(fieldMapping.sqlColumnName(), fieldMapping.protoFieldName());
                    }
                    return "v.\"%s\" AS \"%s\"".formatted(fieldMapping.sqlColumnName(), fieldMapping.protoFieldName());
                })
                .collect(Collectors.toList());

        if (vulnRequirements.contains("aliases")) {
            sqlSelectColumns.add("JSONB_VULN_ALIASES(v.\"SOURCE\", v.\"VULNID\") AS \"aliases\"");
        }
        if (vulnRequirements.contains("epss_score")) {
            sqlSelectColumns.add("e.\"SCORE\" AS \"epss_score\"");
        }
        if (vulnRequirements.contains("epss_percentile")) {
            sqlSelectColumns.add("e.\"PERCENTILE\" AS \"epss_percentile\"");
        }

        return getVulnerabilities(sqlSelectColumns, vulnIds);
    }

}
