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
            SELECT
              ${fetchColumns?join(", ")}
            FROM
              "PROJECT" AS "P"
            <#if fetchColumns?filter(col -> col?contains("\\"metadata_tools\\""))?size gt 0>
              INNER JOIN
                "PROJECT_METADATA" AS "PM" ON "PM"."PROJECT_ID" = "P"."ID"
            </#if>
            <#if fetchColumns?filter(col -> col?contains("\\"bom_generated\\""))?size gt 0>
              INNER JOIN
                "BOM" AS "BM" ON "BM"."PROJECT_ID" = "P"."ID"
            </#if>
            <#if fetchPropertyColumns?size gt 0>
              LEFT JOIN LATERAL (
                SELECT
                  CAST(JSONB_AGG(DISTINCT JSONB_BUILD_OBJECT(${fetchPropertyColumns?join(", ")})) AS TEXT) AS "properties"
                FROM
                  "PROJECT_PROPERTY" AS "PP"
                WHERE
                  "PP"."PROJECT_ID" = "P"."ID"
              ) AS "properties" ON TRUE
            </#if>
            <#if fetchColumns?seq_contains("\\"tags\\"")>
              LEFT JOIN LATERAL (
                SELECT
                  ARRAY_AGG(DISTINCT "T"."NAME") AS "tags"
                FROM
                  "TAG" AS "T"
                INNER JOIN
                  "PROJECTS_TAGS" AS "PT" ON "PT"."TAG_ID" = "T"."ID"
                WHERE
                  "PT"."PROJECT_ID" = "P"."ID"
              ) AS "tags" ON TRUE
            </#if>
            WHERE
              "P"."ID" = :id
            """)
    @RegisterRowMapper(CelPolicyProjectRowMapper.class)
    Project getProject(@Define List<String> fetchColumns, @Define List<String> fetchPropertyColumns, long id);

    @SqlQuery("""
            SELECT
              "C"."ID" AS "db_id"
              <#if fetchColumns?size gt 0>, ${fetchColumns?join(", ")}</#if>
            FROM
              "COMPONENT" AS "C"
            <#if fetchColumns?seq_contains("\\"published_at\\"")>
              LEFT JOIN LATERAL (
                SELECT
                  "IMC"."PUBLISHED_AT" AS "published_at"
                FROM
                  "INTEGRITY_META_COMPONENT" AS "IMC"
                WHERE
                  "IMC"."PURL" = "C"."PURL"
              ) AS "integrityMeta" ON TRUE
            </#if>
            <#if fetchColumns?seq_contains("\\"latest_version\\"")>
              LEFT JOIN LATERAL (
                SELECT
                  "RMC"."LATEST_VERSION" AS "latest_version"
                FROM
                  "REPOSITORY_META_COMPONENT" AS "RMC"
                WHERE
                  "RMC"."NAME" = "C"."NAME"
              ) AS "repoMeta" ON TRUE
            </#if>
            WHERE
              "C"."ID" = ANY(:ids)
            """)
    @KeyColumn("db_id")
    @RegisterRowMapper(CelPolicyComponentRowMapper.class)
    Map<Long, Component> getComponents(@Define List<String> fetchColumns, long[] ids);

    @SqlQuery("""
            SELECT DISTINCT
              "V"."ID" AS "db_id"
              <#if fetchColumns?size gt 0>, ${fetchColumns?join(", ")}</#if>
            FROM
              "VULNERABILITY" AS "V"
            <#if fetchColumns?seq_contains("\\"aliases\\"")>
              LEFT JOIN LATERAL (
                SELECT
                  CAST(JSONB_AGG(DISTINCT JSONB_STRIP_NULLS(JSONB_BUILD_OBJECT(
                    'cveId',      "VA"."CVE_ID",
                    'ghsaId',     "VA"."GHSA_ID",
                    'gsdId',      "VA"."GSD_ID",
                    'internalId', "VA"."INTERNAL_ID",
                    'osvId',      "VA"."OSV_ID",
                    'sonatypeId', "VA"."SONATYPE_ID",
                    'snykId',     "VA"."SNYK_ID",
                    'vulnDbId',   "VA"."VULNDB_ID"
                  ))) AS TEXT) AS "aliases"
                FROM
                  "VULNERABILITYALIAS" AS "VA"
                WHERE
                  ("V"."SOURCE" = 'NVD' AND "VA"."CVE_ID" = "V"."VULNID")
                    OR ("V"."SOURCE" = 'GITHUB' AND "VA"."GHSA_ID" = "V"."VULNID")
                    OR ("V"."SOURCE" = 'GSD' AND "VA"."GSD_ID" = "V"."VULNID")
                    OR ("V"."SOURCE" = 'INTERNAL' AND "VA"."INTERNAL_ID" = "V"."VULNID")
                    OR ("V"."SOURCE" = 'OSV' AND "VA"."OSV_ID" = "V"."VULNID")
                    OR ("V"."SOURCE" = 'SONATYPE' AND "VA"."SONATYPE_ID" = "V"."VULNID")
                    OR ("V"."SOURCE" = 'SNYK' AND "VA"."SNYK_ID" = "V"."VULNID")
                    OR ("V"."SOURCE" = 'VULNDB' AND "VA"."VULNDB_ID" = "V"."VULNID")
              ) AS "aliases" ON TRUE
            </#if>
            <#if fetchColumns?seq_contains("\\"EP\\".\\"SCORE\\" AS \\"epss_score\\"") || fetchColumns?seq_contains("\\"EP\\".\\"PERCENTILE\\" AS \\"epss_percentile\\"")>
                LEFT JOIN "EPSS" AS "EP" ON "V"."VULNID" = "EP"."CVE"
            </#if>
            WHERE
              "V"."ID" = ANY(:ids)
            """)
    @KeyColumn("db_id")
    @RegisterRowMapper(CelPolicyVulnerabilityRowMapper.class)
    Map<Long, Vulnerability> getVulnerabilities(@Define List<String> fetchColumns, long[] ids);

    default Project loadRequiredFields(long projectId, final MultiValuedMap<Type, String> requirements) {
        final Collection<String> projectRequirements = requirements.get(TYPE_PROJECT);
        if (projectRequirements == null || projectRequirements.isEmpty()) {
            return Project.getDefaultInstance();
        }

        final List<String> sqlSelectColumns = getFieldMappings(ProjectProjection.class).stream()
                .filter(fieldMapping -> projectRequirements.contains(fieldMapping.protoFieldName()))
                .map(fieldMapping -> "\"P\".\"%s\" AS \"%s\"".formatted(fieldMapping.sqlColumnName(), fieldMapping.protoFieldName()))
                .collect(Collectors.toList());

        if (projectRequirements.contains("metadata")
            && requirements.containsKey(TYPE_PROJECT_METADATA)) {
            if (requirements.get(TYPE_PROJECT_METADATA).contains("tools")) {
                sqlSelectColumns.add("\"PM\".\"TOOLS\" AS \"metadata_tools\"");
            }
            if (requirements.get(TYPE_PROJECT_METADATA).contains("bom_generated")) {
                sqlSelectColumns.add("\"BM\".\"GENERATED\" AS \"bom_generated\"");
            }
        }

        if (projectRequirements.contains("is_active")) {
            sqlSelectColumns.add("\"P\".\"INACTIVE_SINCE\" AS \"inactive_since\"");
        }

        final var sqlPropertySelectColumns = new ArrayList<String>();
        if (projectRequirements.contains("properties") && requirements.containsKey(TYPE_PROJECT_PROPERTY)) {
            sqlSelectColumns.add("\"properties\"");

            getFieldMappings(ProjectPropertyProjection.class).stream()
                    .filter(mapping -> requirements.get(TYPE_PROJECT_PROPERTY).contains(mapping.protoFieldName()))
                    .map(mapping -> "'%s', \"PP\".\"%s\"".formatted(mapping.protoFieldName(), mapping.sqlColumnName()))
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

    /**
     * Batch-load required fields for multiple {@link Component}s in a single query.
     *
     * @return A {@link Map} keyed by component DB ID, containing components with required fields loaded
     */
    default Map<Long, Component> loadRequiredComponentFields(final Collection<Long> componentIds,
                                                             final MultiValuedMap<Type, String> requirements) {
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
                .map(fieldMapping -> "\"C\".\"%s\" AS \"%s\"".formatted(fieldMapping.sqlColumnName(), fieldMapping.protoFieldName()))
                .collect(Collectors.toList());

        if (componentRequirements.contains("latest_version")) {
            sqlSelectColumns.add("\"latest_version\"");
        }
        if (componentRequirements.contains("published_at")) {
            sqlSelectColumns.add("\"published_at\"");
        }

        return getComponents(sqlSelectColumns, componentIds.stream().mapToLong(Long::longValue).toArray());
    }

    /**
     * Batch-load required fields for multiple {@link Vulnerability}s in a single query.
     *
     * @return A {@link Map} keyed by vulnerability DB ID, containing vulnerabilities with required fields loaded
     */
    default Map<Long, Vulnerability> loadRequiredVulnerabilityFields(final Collection<Long> vulnIds,
                                                                     final MultiValuedMap<Type, String> requirements) {
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
                        return "STRING_TO_ARRAY(\"V\".\"%s\", ',') AS \"%s\""
                                .formatted(fieldMapping.sqlColumnName(), fieldMapping.protoFieldName());
                    }
                    return "\"V\".\"%s\" AS \"%s\"".formatted(fieldMapping.sqlColumnName(), fieldMapping.protoFieldName());
                })
                .collect(Collectors.toList());

        if (vulnRequirements.contains("aliases")) {
            sqlSelectColumns.add("\"aliases\"");
        }
        if (vulnRequirements.contains("epss_score")) {
            sqlSelectColumns.add("\"EP\".\"SCORE\" AS \"epss_score\"");
        }
        if (vulnRequirements.contains("epss_percentile")) {
            sqlSelectColumns.add("\"EP\".\"PERCENTILE\" AS \"epss_percentile\"");
        }

        return getVulnerabilities(sqlSelectColumns, vulnIds.stream().mapToLong(Long::longValue).toArray());
    }

}
