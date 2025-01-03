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
import com.google.protobuf.Descriptors.Descriptor;
import com.google.protobuf.Descriptors.FieldDescriptor;
import com.google.protobuf.Message;
import org.apache.commons.collections4.MultiValuedMap;
import org.dependencytrack.policy.cel.mapping.ComponentProjection;
import org.dependencytrack.policy.cel.mapping.ProjectProjection;
import org.dependencytrack.policy.cel.mapping.ProjectPropertyProjection;
import org.dependencytrack.policy.cel.mapping.VulnerabilityProjection;
import org.dependencytrack.proto.policy.v1.Component;
import org.dependencytrack.proto.policy.v1.Project;
import org.dependencytrack.proto.policy.v1.Vulnerability;
import org.jdbi.v3.sqlobject.config.RegisterRowMapper;
import org.jdbi.v3.sqlobject.customizer.Define;
import org.jdbi.v3.sqlobject.statement.SqlQuery;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.UUID;
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
              "P"."UUID" = :uuid
            """)
    @RegisterRowMapper(CelPolicyProjectRowMapper.class)
    Project getProject(@Define List<String> fetchColumns, @Define List<String> fetchPropertyColumns, UUID uuid);

    @SqlQuery("""
            SELECT
              ${fetchColumns?join(", ")}
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
              "C"."UUID" = :uuid
            """)
    @RegisterRowMapper(CelPolicyComponentRowMapper.class)
    Component getComponent(@Define List<String> fetchColumns, UUID uuid);

    @SqlQuery("""
            SELECT DISTINCT
              ${fetchColumns?join(", ")}
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
              "V"."UUID" = :uuid
            """)
    @RegisterRowMapper(CelPolicyVulnerabilityRowMapper.class)
    Vulnerability getVulnerability(@Define List<String> fetchColumns, UUID uuid);

    default Project loadRequiredFields(final Project project, final MultiValuedMap<Type, String> requirements) {
        final Collection<String> projectRequirements = requirements.get(TYPE_PROJECT);
        if (projectRequirements == null || projectRequirements.isEmpty()) {
            return project;
        }

        final Set<String> fieldsToLoad = determineFieldsToLoad(Project.getDescriptor(), project, projectRequirements);
        if (fieldsToLoad.isEmpty()) {
            LOGGER.debug("All required fields are already loaded for message of type %s"
                    .formatted(Project.getDescriptor().getFullName()));
            return project;
        }

        final List<String> sqlSelectColumns = getFieldMappings(ProjectProjection.class).stream()
                .filter(fieldMapping -> fieldsToLoad.contains(fieldMapping.protoFieldName()))
                .map(fieldMapping -> "\"P\".\"%s\" AS \"%s\"".formatted(fieldMapping.sqlColumnName(), fieldMapping.protoFieldName()))
                .collect(Collectors.toList());

        if (fieldsToLoad.contains("metadata")
            && requirements.containsKey(TYPE_PROJECT_METADATA)) {
            if (requirements.get(TYPE_PROJECT_METADATA).contains("tools")) {
                sqlSelectColumns.add("\"PM\".\"TOOLS\" AS \"metadata_tools\"");
            }
            if (requirements.get(TYPE_PROJECT_METADATA).contains("bom_generated")) {
                sqlSelectColumns.add("\"BM\".\"GENERATED\" AS \"bom_generated\"");
            }
        }

        if (fieldsToLoad.contains("is_active")) {
            sqlSelectColumns.add("\"P\".\"INACTIVE_SINCE\" AS \"inactive_since\"");
        }

        final var sqlPropertySelectColumns = new ArrayList<String>();
        if (fieldsToLoad.contains("properties") && requirements.containsKey(TYPE_PROJECT_PROPERTY)) {
            sqlSelectColumns.add("\"properties\"");

            getFieldMappings(ProjectPropertyProjection.class).stream()
                    .filter(mapping -> requirements.get(TYPE_PROJECT_PROPERTY).contains(mapping.protoFieldName()))
                    .map(mapping -> "'%s', \"PP\".\"%s\"".formatted(mapping.protoFieldName(), mapping.sqlColumnName()))
                    .forEach(sqlPropertySelectColumns::add);
        }
        if (fieldsToLoad.contains("tags")) {
            sqlSelectColumns.add("\"tags\"");
        }

        final Project fetchedProject = getProject(sqlSelectColumns, sqlPropertySelectColumns, UUID.fromString(project.getUuid()));
        if (fetchedProject == null) {
            throw new NoSuchElementException();
        }

        return project.toBuilder().mergeFrom(fetchedProject).build();
    }

    default Component loadRequiredFields(final Component component, final MultiValuedMap<Type, String> requirements) {
        final Collection<String> componentRequirements = requirements.get(TYPE_COMPONENT);
        if (componentRequirements == null || componentRequirements.isEmpty()) {
            return component;
        }

        final Set<String> fieldsToLoad = determineFieldsToLoad(Component.getDescriptor(), component, componentRequirements);
        if (fieldsToLoad.isEmpty()) {
            LOGGER.debug("All required fields are already loaded for message of type %s"
                    .formatted(Component.getDescriptor().getFullName()));
            return component;
        }

        final List<String> sqlSelectColumns = getFieldMappings(ComponentProjection.class).stream()
                .filter(fieldMapping -> fieldsToLoad.contains(fieldMapping.protoFieldName()))
                .map(fieldMapping -> "\"C\".\"%s\" AS \"%s\"".formatted(fieldMapping.sqlColumnName(), fieldMapping.protoFieldName()))
                .collect(Collectors.toList());
        if (fieldsToLoad.contains("latest_version")) {
            sqlSelectColumns.add("\"latest_version\"");
        }
        if (fieldsToLoad.contains("published_at")) {
            sqlSelectColumns.add("\"published_at\"");
        }

        final Component fetchedComponent = getComponent(sqlSelectColumns, UUID.fromString(component.getUuid()));
        if (fetchedComponent == null) {
            throw new NoSuchElementException();
        }

        return component.toBuilder().mergeFrom(fetchedComponent).build();
    }

    default Vulnerability loadRequiredFields(final Vulnerability vuln, final MultiValuedMap<Type, String> requirements) {
        final Collection<String> vulnRequirements = requirements.get(TYPE_VULNERABILITY);
        if (vulnRequirements == null || vulnRequirements.isEmpty()) {
            return vuln;
        }

        final Set<String> fieldsToLoad = determineFieldsToLoad(Vulnerability.getDescriptor(), vuln, vulnRequirements);
        if (fieldsToLoad.isEmpty()) {
            LOGGER.debug("All required fields are already loaded for message of type %s"
                    .formatted(Vulnerability.getDescriptor().getFullName()));
            return vuln;
        }

        final List<String> sqlSelectColumns = getFieldMappings(VulnerabilityProjection.class).stream()
                .filter(fieldMapping -> fieldsToLoad.contains(fieldMapping.protoFieldName()))
                .map(fieldMapping -> {
                    if ("cwes".equals(fieldMapping.protoFieldName())) {
                        return "STRING_TO_ARRAY(\"V\".\"%s\", ',') AS \"%s\""
                                .formatted(fieldMapping.sqlColumnName(), fieldMapping.protoFieldName());
                    }

                    return "\"V\".\"%s\" AS \"%s\"".formatted(fieldMapping.sqlColumnName(), fieldMapping.protoFieldName());
                })
                .collect(Collectors.toList());
        if (fieldsToLoad.contains("aliases")) {
            sqlSelectColumns.add("\"aliases\"");
        }
        if (fieldsToLoad.contains("epss_score")) {
            sqlSelectColumns.add("\"EP\".\"SCORE\" AS \"epss_score\"");
        }
        if (fieldsToLoad.contains("epss_percentile")) {
            sqlSelectColumns.add("\"EP\".\"PERCENTILE\" AS \"epss_percentile\"");
        }
        final Vulnerability fetchedVuln = getVulnerability(sqlSelectColumns, UUID.fromString(vuln.getUuid()));
        if (fetchedVuln == null) {
            throw new NoSuchElementException();
        }

        return vuln.toBuilder().mergeFrom(fetchedVuln).build();
    }

    private static Set<String> determineFieldsToLoad(final Descriptor typeDescriptor, final Message typeInstance, final Collection<String> requiredFields) {
        final var fieldsToLoad = new HashSet<String>();
        for (final String fieldName : requiredFields) {
            final FieldDescriptor fieldDescriptor = typeDescriptor.findFieldByName(fieldName);
            if (fieldDescriptor == null) {
                LOGGER.warn("Field %s is required but does not exist for type %s"
                        .formatted(fieldName, typeDescriptor.getFullName()));
                continue;
            }

            if (fieldDescriptor.isRepeated() && typeInstance.getRepeatedFieldCount(fieldDescriptor) == 0) {
                // There's no way differentiate between repeated fields being not set or just empty.
                fieldsToLoad.add(fieldName);
            } else if (!fieldDescriptor.isRepeated() && !typeInstance.hasField(fieldDescriptor)) {
                fieldsToLoad.add(fieldName);
            }
        }
        return fieldsToLoad;
    }

}
