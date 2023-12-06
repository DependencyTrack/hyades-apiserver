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
import org.dependencytrack.proto.policy.v1.Component;
import org.dependencytrack.proto.policy.v1.Project;
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
import static org.dependencytrack.policy.cel.definition.CelPolicyTypes.TYPE_PROJECT_PROPERTY;
import static org.dependencytrack.policy.cel.mapping.FieldMappingUtil.getFieldMappings;

public interface CelPolicyDao {

    Logger LOGGER = Logger.getLogger(CelPolicyDao.class);

    @SqlQuery("""
            SELECT
              ${fetchColumns?join(", ")}
            FROM
              "PROJECT" AS "P"
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
                CAST(JSONB_AGG(DISTINCT "T"."NAME") AS TEXT) AS "tags"
              FROM
                "TAG" AS "T"
              INNER JOIN
                "PROJECTS_TAGS" AS "PT" ON "PT"."TAG_ID" = "T"."ID"
              WHERE
                "PT"."PROJECT_ID" = "P"."ID"
            ) AS "tags" ON TRUE
            </#if>
            WHERE
              "P"."UUID" = (:uuid)::TEXT
            """)
    @RegisterRowMapper(CelPolicyProjectRowMapper.class)
    Project getProject(@Define List<String> fetchColumns, @Define List<String> fetchPropertyColumns, UUID uuid);

    @SqlQuery("""
            SELECT
              ${fetchColumns?join(", ")}
            FROM
              "COMPONENT" AS "C"
            <#if fetchColumns?seq_contains(\\"publishedAt\\")>
            LEFT JOIN LATERAL (
              SELECT
                "IMC"."PUBLISHED_AT" AS "publishedAt"
              FROM
                "INTEGRITY_META_COMPONENT" AS "IMC"
              WHERE
                "IMC"."PURL" = "C"."PURL"
            ) AS "integrityMeta"
            </#if>
            <#if fetchColumns?seq_contains(\\"latestVersion\\")>
            LEFT JOIN LATERAL (
              SELECT
                "RMC"."LATEST_VERSION" AS "latestVersion"
              FROM
                "REPOSITORY_META_COMPONENT" AS "RMC"
              WHERE
                "RMC"."NAME" = "C"."NAME"
            ) AS "repoMeta"
            </#if>
            WHERE
              "C"."UUID" = (:uuid)::TEXT
            """)
    @RegisterRowMapper(CelPolicyComponentRowMapper.class)
    Component getComponent(@Define List<String> fetchColumns, UUID uuid);

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
        final Collection<String> projectRequirements = requirements.get(TYPE_COMPONENT);
        if (projectRequirements == null || projectRequirements.isEmpty()) {
            return component;
        }

        final Set<String> fieldsToLoad = determineFieldsToLoad(Component.getDescriptor(), component, projectRequirements);
        if (fieldsToLoad.isEmpty()) {
            LOGGER.debug("All required fields are already loaded for message of type %s"
                    .formatted(Component.getDescriptor().getFullName()));
            return component;
        }

        final List<String> sqlSelectColumns = getFieldMappings(ComponentProjection.class).stream()
                .filter(fieldMapping -> fieldsToLoad.contains(fieldMapping.protoFieldName()))
                .map(fieldMapping -> "\"C\".\"%s\" AS \"%s\"".formatted(fieldMapping.sqlColumnName(), fieldMapping.javaFieldName()))
                .collect(Collectors.toList());
        if (fieldsToLoad.contains("latest_version")) {
            sqlSelectColumns.add("\"latestVersion\"");
        }
        if (fieldsToLoad.contains("published_at")) {
            sqlSelectColumns.add("\"publishedAt\"");
        }

        final Component fetchedComponent = getComponent(sqlSelectColumns, UUID.fromString(component.getUuid()));
        if (fetchedComponent == null) {
            throw new NoSuchElementException();
        }

        return component.toBuilder().mergeFrom(fetchedComponent).build();
    }

    private static Set<String> determineFieldsToLoad(final Descriptor typeDescriptor, final Message typeInstance, final Collection<String> requiredFields) {
        final var fieldsToLoad = new HashSet<String>();
        for (final String fieldName : requiredFields) {
            final FieldDescriptor fieldDescriptor = Project.getDescriptor().findFieldByName(fieldName);
            if (fieldDescriptor == null) {
                LOGGER.warn("Field %s is required but does not exist for type %s"
                        .formatted(fieldName, typeDescriptor.getFullName()));
                continue;
            }

            if (fieldDescriptor.isRepeated() && typeInstance.getRepeatedFieldCount(fieldDescriptor) == 0) {
                // There's no way differentiate between repeated fields being not set or just empty.
                fieldsToLoad.add(fieldName);
            } else if (!typeInstance.hasField(fieldDescriptor)) {
                fieldsToLoad.add(fieldName);
            }
        }
        return fieldsToLoad;
    }

}
