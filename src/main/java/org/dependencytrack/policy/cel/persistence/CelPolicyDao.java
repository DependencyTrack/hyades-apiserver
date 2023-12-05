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
import org.dependencytrack.proto.policy.v1.Vulnerability;
import org.jdbi.v3.core.Handle;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.dependencytrack.policy.cel.definition.CelPolicyTypes.TYPE_COMPONENT;
import static org.dependencytrack.policy.cel.definition.CelPolicyTypes.TYPE_PROJECT;
import static org.dependencytrack.policy.cel.definition.CelPolicyTypes.TYPE_PROJECT_PROPERTY;
import static org.dependencytrack.policy.cel.mapping.FieldMappingUtil.getFieldMappings;

public class CelPolicyDao {

    private static final Logger LOGGER = Logger.getLogger(CelPolicyDao.class);

    public Project loadRequiredFields(final Handle jdbiHandle, final Project project, final MultiValuedMap<Type, String> requirements) {
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

        return jdbiHandle.createQuery("""
                        SELECT
                          <selectColumns>
                        FROM
                          "PROJECT" AS "P"
                        <if(shouldFetchProperties)>
                        LEFT JOIN LATERAL (
                          SELECT
                            CAST(JSONB_AGG(DISTINCT JSONB_BUILD_OBJECT(<propertySelectColumns>)) AS TEXT) AS "properties"
                          FROM
                            "PROJECT_PROPERTY" AS "PP"
                          WHERE
                            "PP"."PROJECT_ID" = "P"."ID"
                        ) AS "properties" ON TRUE
                        <endif>
                        <if(shouldFetchTags)>
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
                        <endif>
                        WHERE
                          "P"."UUID" = :uuid
                        """)
                .defineList("selectColumns", sqlSelectColumns)
                .defineList("propertySelectColumns", sqlPropertySelectColumns)
                .define("shouldFetchProperties", sqlSelectColumns.contains("\"properties\""))
                .define("shouldFetchTags", sqlSelectColumns.contains("\"tags\""))
                .bind("uuid", project.getUuid())
                .map(new CelPolicyProjectRowMapper(project.toBuilder()))
                .one();
    }

    public Component loadRequiredFields(final Handle jdbiHandle, final Component component, final MultiValuedMap<Type, String> requirements) {
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

        return jdbiHandle.createQuery("""
                        SELECT
                          <selectColumns>
                        FROM
                          "COMPONENT" AS "C"
                        <if(shouldFetchPublishedAt)>
                        LEFT JOIN LATERAL (
                          SELECT
                            "IMC"."PUBLISHED_AT" AS "publishedAt"
                          FROM
                            "INTEGRITY_META_COMPONENT" AS "IMC"
                          WHERE
                            "IMC"."PURL" = "C"."PURL"
                        ) AS "integrityMeta"
                        <endif>
                        <if(shouldFetchLatestVersion)>
                        LEFT JOIN LATERAL (
                          SELECT
                            "RMC"."LATEST_VERSION" AS "latestVersion"
                          FROM
                            "REPOSITORY_META_COMPONENT" AS "RMC"
                          WHERE
                            "RMC"."NAME" = "C"."NAME"
                        ) AS "repoMeta"
                        <endif>
                        WHERE
                          "C"."UUID" = :uuid
                        """)
                .defineList("selectColumns", sqlSelectColumns)
                .define("shouldFetchLatestVersion", sqlSelectColumns.contains("\"latestVersion\""))
                .define("shouldFetchPublishedAt", sqlSelectColumns.contains("\"publishedAt\""))
                .bind("uuid", component.getUuid())
                .map(new CelPolicyComponentRowMapper(component.toBuilder()))
                .one();
    }

    public Vulnerability loadRequiredFields(final Handle jdbiHandle, final Vulnerability vuln, final MultiValuedMap<Type, String> requirements) {
        return jdbiHandle.createQuery("""
                        """)
                .map(new CelPolicyVulnerabilityRowMapper(vuln.toBuilder()))
                .one();
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
