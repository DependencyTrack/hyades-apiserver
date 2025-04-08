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
package org.dependencytrack.policy.cel;

import alpine.common.logging.Logger;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import io.github.nscuro.versatile.Vers;
import io.github.nscuro.versatile.VersException;
import org.dependencytrack.model.RepositoryType;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.proto.policy.v1.Component;
import org.dependencytrack.proto.policy.v1.License;
import org.dependencytrack.proto.policy.v1.Project;
import org.dependencytrack.proto.policy.v1.Tools;
import org.dependencytrack.proto.policy.v1.VersionDistance;
import org.dependencytrack.proto.policy.v1.Vulnerability;
import org.jdbi.v3.core.Handle;
import org.jdbi.v3.core.mapper.reflect.ConstructorMapper;
import org.jdbi.v3.core.statement.Query;
import org.projectnessie.cel.EnvOption;
import org.projectnessie.cel.Library;
import org.projectnessie.cel.ProgramOption;
import org.projectnessie.cel.checker.Decls;
import org.projectnessie.cel.common.types.BoolT;
import org.projectnessie.cel.common.types.Err;
import org.projectnessie.cel.common.types.Types;
import org.projectnessie.cel.common.types.ref.Val;
import org.projectnessie.cel.interpreter.functions.Overload;

import jakarta.annotation.Nullable;
import java.time.Instant;
import java.time.LocalDate;
import java.time.Period;
import java.time.ZoneId;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import static org.apache.commons.lang3.StringUtils.substringAfter;
import static org.dependencytrack.persistence.jdbi.JdbiAttributes.ATTRIBUTE_QUERY_NAME;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.openJdbiHandle;
import static org.dependencytrack.policy.cel.definition.CelPolicyTypes.TYPE_COMPONENT;
import static org.dependencytrack.policy.cel.definition.CelPolicyTypes.TYPE_PROJECT;
import static org.dependencytrack.policy.cel.definition.CelPolicyTypes.TYPE_VERSION_DISTANCE;

public class CelCommonPolicyLibrary implements Library {

    private static final Logger LOGGER = Logger.getLogger(CelCommonPolicyLibrary.class);

    static final String FUNC_DEPENDS_ON = "depends_on";
    static final String FUNC_IS_DEPENDENCY_OF = "is_dependency_of";
    static final String FUNC_IS_EXCLUSIVE_DEPENDENCY_OF = "is_exclusive_dependency_of";
    static final String FUNC_MATCHES_RANGE = "matches_range";
    static final String FUNC_COMPARE_AGE = "compare_age";
    static final String FUNC_COMPARE_VERSION_DISTANCE = "version_distance";

    @Override
    public List<EnvOption> getCompileOptions() {
        return List.of(
                EnvOption.container("org.dependencytrack.policy"),
                EnvOption.declarations(
                        Decls.newFunction(
                                FUNC_DEPENDS_ON,
                                // project.depends_on(v1.Component{name: "foo"})
                                Decls.newInstanceOverload(
                                        "project_depends_on_component_bool",
                                        List.of(TYPE_PROJECT, TYPE_COMPONENT),
                                        Decls.Bool
                                )
                        ),
                        Decls.newFunction(
                                FUNC_IS_DEPENDENCY_OF,
                                // component.is_dependency_of(v1.Component{name: "foo"})
                                Decls.newInstanceOverload(
                                        "component_is_dependency_of_component_bool",
                                        List.of(TYPE_COMPONENT, TYPE_COMPONENT),
                                        Decls.Bool
                                )
                        ),
                        Decls.newFunction(
                                FUNC_IS_EXCLUSIVE_DEPENDENCY_OF,
                                // component.is_exclusive_dependency_of(v1.Component{name: "foo"})
                                Decls.newInstanceOverload(
                                        "component_is_exclusive_dependency_of_component_bool",
                                        List.of(TYPE_COMPONENT, TYPE_COMPONENT),
                                        Decls.Bool
                                )
                        ),
                        Decls.newFunction(
                                FUNC_MATCHES_RANGE,
                                // component.matches_range("vers:golang/>0|!=v3.2.1")
                                Decls.newInstanceOverload(
                                        "component_matches_range_bool",
                                        List.of(TYPE_COMPONENT, Decls.String),
                                        Decls.Bool
                                ),
                                // project.matches_range("vers:golang/>0|!=v3.2.1")
                                Decls.newInstanceOverload(
                                        "project_matches_range_bool",
                                        List.of(TYPE_PROJECT, Decls.String),
                                        Decls.Bool
                                )
                        ),
                        Decls.newFunction(
                                FUNC_COMPARE_AGE,
                                Decls.newInstanceOverload(
                                        "compare_age_bool",
                                        List.of(TYPE_COMPONENT, Decls.String, Decls.String),
                                        Decls.Bool
                                )
                        ),
                        Decls.newFunction(
                                FUNC_COMPARE_VERSION_DISTANCE,
                                Decls.newInstanceOverload(
                                        "matches_version_distance_bool",
                                        List.of(TYPE_COMPONENT, Decls.String, TYPE_VERSION_DISTANCE),
                                        Decls.Bool
                                )
                        )
                ),
                EnvOption.types(
                        Component.getDefaultInstance(),
                        License.getDefaultInstance(),
                        License.Group.getDefaultInstance(),
                        Project.getDefaultInstance(),
                        Project.Metadata.getDefaultInstance(),
                        Project.Property.getDefaultInstance(),
                        Tools.getDefaultInstance(),
                        Vulnerability.getDefaultInstance(),
                        Vulnerability.Alias.getDefaultInstance(),
                        VersionDistance.getDefaultInstance()
                )
        );
    }

    @Override
    public List<ProgramOption> getProgramOptions() {
        return List.of(
                ProgramOption.functions(
                        Overload.binary(
                                FUNC_DEPENDS_ON,
                                CelCommonPolicyLibrary::dependsOnFunc
                        ),
                        Overload.binary(
                                FUNC_IS_DEPENDENCY_OF,
                                CelCommonPolicyLibrary::isDependencyOfFunc
                        ),
                        Overload.binary(
                                FUNC_IS_EXCLUSIVE_DEPENDENCY_OF,
                                CelCommonPolicyLibrary::isExclusiveDependencyOfFunc
                        ),
                        Overload.binary(
                                FUNC_MATCHES_RANGE,
                                CelCommonPolicyLibrary::matchesRangeFunc
                        ),
                        Overload.function(FUNC_COMPARE_AGE,
                                CelCommonPolicyLibrary::isComponentOldFunc),
                        Overload.function(FUNC_COMPARE_VERSION_DISTANCE,
                                CelCommonPolicyLibrary::matchesVersionDistanceFunc)
                )
        );
    }

    private static Val matchesVersionDistanceFunc(Val... vals) {
        try {
            var basicCheckResult = basicVersionDistanceCheck(vals);
            if ((basicCheckResult instanceof BoolT && basicCheckResult.value() == Types.boolOf(false)) || basicCheckResult instanceof Err) {
                return basicCheckResult;
            }
            var component = (Component) vals[0].value();
            var comparator = (String) vals[1].value();
            var value = (VersionDistance) vals[2].value();
            if (!component.hasLatestVersion()) {
                return Err.newErr("Requested component does not have latest version information", component);
            }
            return Types.boolOf(matchesVersionDistance(component, comparator, value));
        }catch (Exception ex) {
            LOGGER.warn("""
                    %s: Was unable to parse dynamic message for version distance policy;
                    Unable to resolve, returning false""".formatted(FUNC_COMPARE_VERSION_DISTANCE));
            return Types.boolOf(false);
        }
    }

    private static boolean matchesVersionDistance(Component component, String comparator, VersionDistance value) {
        String comparatorComputed = switch (comparator) {
            case "NUMERIC_GREATER_THAN", ">" -> "NUMERIC_GREATER_THAN";
            case "NUMERIC_GREATER_THAN_OR_EQUAL", ">=" -> "NUMERIC_GREATER_THAN_OR_EQUAL";
            case "NUMERIC_EQUAL", "==" -> "NUMERIC_EQUAL";
            case "NUMERIC_NOT_EQUAL", "!=" -> "NUMERIC_NOT_EQUAL";
            case "NUMERIC_LESSER_THAN_OR_EQUAL", "<=" -> "NUMERIC_LESSER_THAN_OR_EQUAL";
            case "NUMERIC_LESS_THAN", "<" -> "NUMERIC_LESS_THAN";
            default -> "";
        };
        if (comparatorComputed.isEmpty()) {
            LOGGER.warn("""
                    %s: Was passed a not supported operator : %s for version distance policy;
                    Unable to resolve, returning false""".formatted(FUNC_COMPARE_VERSION_DISTANCE, comparator));
            return false;
        }
        final org.dependencytrack.model.VersionDistance versionDistance;
        try {
            versionDistance = org.dependencytrack.model.VersionDistance.getVersionDistance(component.getVersion(), component.getLatestVersion());
        } catch (RuntimeException e) {
            LOGGER.warn("""
                    %s: Failed to compute version distance for component %s (UUID: %s), \
                    between component version %s and latest version %s; Skipping\
                    """.formatted(FUNC_COMPARE_VERSION_DISTANCE, component, component.getUuid(), component.getVersion(), component.getLatestVersion()), e);
            return false;
        }
        final boolean isDirectDependency;
        try (final var qm = new QueryManager();
             final var celQm = new CelPolicyQueryManager(qm)) {
            isDirectDependency = celQm.isDirectDependency(component);
        }
        return isDirectDependency && org.dependencytrack.model.VersionDistance.evaluate(value, comparatorComputed, versionDistance);
    }

    private static Val dependsOnFunc(final Val lhs, final Val rhs) {
        final Component leafComponent;
        if (rhs.value() instanceof final Component rhsValue) {
            leafComponent = rhsValue;
        } else {
            return Err.maybeNoSuchOverloadErr(rhs);
        }

        if (lhs.value() instanceof final Project project) {
            // project.depends_on(v1.Component{name: "foo"})
            return Types.boolOf(dependsOn(project, leafComponent));
        }

        return Err.maybeNoSuchOverloadErr(lhs);
    }

    private static Val isExclusiveDependencyOfFunc(final Val lhs, final Val rhs) {
        final Component leafComponent;
        if (lhs.value() instanceof final Component lhsValue) {
            leafComponent = lhsValue;
        } else {
            return Err.maybeNoSuchOverloadErr(lhs);
        }

        if (rhs.value() instanceof final Component rootComponent) {
            return Types.boolOf(isExclusiveDependencyOf(leafComponent, rootComponent));
        }

        return Err.maybeNoSuchOverloadErr(rhs);
    }

    private static Val isDependencyOfFunc(final Val lhs, final Val rhs) {
        final Component leafComponent;
        if (lhs.value() instanceof final Component lhsValue) {
            leafComponent = lhsValue;
        } else {
            return Err.maybeNoSuchOverloadErr(lhs);
        }

        if (rhs.value() instanceof final Component rootComponent) {
            return Types.boolOf(isDependencyOf(leafComponent, rootComponent));
        }

        return Err.maybeNoSuchOverloadErr(rhs);
    }

    private static Val matchesRangeFunc(final Val lhs, final Val rhs) {
        final String version;
        if (lhs.value() instanceof final Component lhsValue) {
            // component.matches_range("vers:golang/>0|!=v3.2.1")
            version = lhsValue.getVersion();
        } else if (lhs.value() instanceof final Project lhsValue) {
            // project.matches_range("vers:golang/>0|!=v3.2.1")
            version = lhsValue.getVersion();
        } else {
            return Err.maybeNoSuchOverloadErr(lhs);
        }

        final String versStr;
        if (rhs.value() instanceof final String rhsValue) {
            versStr = rhsValue;
        } else {
            return Err.maybeNoSuchOverloadErr(rhs);
        }

        return Types.boolOf(matchesRange(version, versStr));
    }

    private static Val isComponentOldFunc(Val... vals) {
        Val basicCheckResult = basicCheck(vals);
        if ((basicCheckResult instanceof BoolT && basicCheckResult.value().equals(Types.boolOf(false))) || basicCheckResult instanceof Err) {
            return basicCheckResult;
        }
        final var component = (Component) vals[0].value();
        final var dateValue = (String) vals[2].value();
        final var comparator = (String) vals[1].value();
        return Types.boolOf(isComponentOld(component, comparator, dateValue));
    }

    private static Val basicVersionDistanceCheck(Val... vals) {

        if (vals.length != 3) {
            return Types.boolOf(false);
        }
        Val[] subVals = {vals[0], vals[1]};
        Val basicCheckResult = basicPartsCheck(subVals);
        if ((basicCheckResult instanceof BoolT && basicCheckResult.value().equals(Types.boolOf(false))) || basicCheckResult instanceof Err) {
            return basicCheckResult;
        }

        if (!(vals[2].value() instanceof VersionDistance)) {
            return Err.maybeNoSuchOverloadErr(vals[2]);
        }
        return Types.boolOf(true);
    }

    private static Val basicPartsCheck(Val... vals) {
        if (vals.length != 2) {
            return Types.boolOf(false);
        }
        if (vals[0].value() == null || vals[1].value() == null) {
            return Types.boolOf(false);
        }

        if (!(vals[0].value() instanceof final Component component)) {
            return Err.maybeNoSuchOverloadErr(vals[0]);
        }
        if (!(vals[1].value() instanceof String)) {
            return Err.maybeNoSuchOverloadErr(vals[1]);
        }

        if (!component.hasPurl()) {
            return Err.newErr("Provided component does not have a purl", vals[0]);
        }
        try {
            if (RepositoryType.resolve(new PackageURL(component.getPurl())) == RepositoryType.UNSUPPORTED) {
                return Err.newErr("Unsupported repository type for component: ", vals[0]);
            }
        } catch (MalformedPackageURLException ex) {
            return Err.newErr("Invalid package url ", component.getPurl());
        }
        return Types.boolOf(true);
    }

    private static Val basicCheck(Val... vals) {
        if (vals.length != 3) {
            return Types.boolOf(false);
        }
        Val[] subVals = {vals[0], vals[1]};
        Val basicCheckResult = basicPartsCheck(subVals);
        if ((basicCheckResult instanceof BoolT && basicCheckResult.value().equals(Types.boolOf(false))) || basicCheckResult instanceof Err) {
            return basicCheckResult;
        }

        if (!(vals[2].value() instanceof String)) {
            return Err.maybeNoSuchOverloadErr(vals[2]);
        }

        return Types.boolOf(true);
    }

    private static boolean dependsOn(final Project project, final Component component) {
        if (project.getUuid().isBlank()) {
            // Need a UUID for our starting point.
            LOGGER.warn("%s: project does not have a UUID; Unable to evaluate, returning false"
                    .formatted(FUNC_DEPENDS_ON));
            return false;
        }

        final var compositeNodeFilter = CompositeDependencyNodeFilter.of(component);
        if (!compositeNodeFilter.hasSqlFilters()) {
            LOGGER.warn("""
                    %s: Unable to construct filter expression from component %s; \
                    Unable to evaluate, returning false""".formatted(FUNC_DEPENDS_ON, component));
            return false;
        }

        // TODO: Result can / should likely be cached based on filter and params.

        try (final Handle jdbiHandle = openJdbiHandle()) {
            if (!compositeNodeFilter.hasInMemoryFilters()) {
                final Query query = jdbiHandle.createQuery("""                     
                        WITH
                        "CTE_PROJECT" AS (
                          SELECT "ID" FROM "PROJECT" WHERE "UUID" = :projectUuid
                        )
                        SELECT
                          COUNT(*)
                        FROM
                          "COMPONENT"
                        WHERE
                          "PROJECT_ID" = (SELECT "ID" FROM "CTE_PROJECT")
                          AND ${filters}
                        """);
                return query
                        .define(ATTRIBUTE_QUERY_NAME, "%s#dependsOn_withoutInMemoryFilters".formatted(CelCommonPolicyLibrary.class.getSimpleName()))
                        .define("filters", compositeNodeFilter.sqlFiltersConjunctive())
                        .bind("projectUuid", UUID.fromString(project.getUuid()))
                        .bindMap(compositeNodeFilter.sqlFilterParams())
                        .mapTo(Long.class)
                        .map(count -> count > 0)
                        .one();
            }

            final Query query = jdbiHandle.createQuery("""
                    WITH
                    "CTE_PROJECT" AS (
                      SELECT "ID" FROM "PROJECT" WHERE "UUID" = :projectUuid
                    )
                    SELECT
                      ${selectColumnNames?join(", ")}
                    FROM
                      "COMPONENT"
                    WHERE
                      "PROJECT_ID" = (SELECT "ID" FROM "CTE_PROJECT")
                      AND ${filters}
                    """);
            return query
                    .define(ATTRIBUTE_QUERY_NAME, "%s#dependsOn_withInMemoryFilters".formatted(CelCommonPolicyLibrary.class.getSimpleName()))
                    .define("filters", compositeNodeFilter.sqlFiltersConjunctive())
                    .define("selectColumnNames", compositeNodeFilter.sqlSelectColumns())
                    .bind("projectUuid", UUID.fromString(project.getUuid()))
                    .bindMap(compositeNodeFilter.sqlFilterParams())
                    .map(ConstructorMapper.of(DependencyNode.class))
                    .stream()
                    .anyMatch(compositeNodeFilter.inMemoryFiltersConjunctive());
        }
    }

    private static boolean dependsOn(final Component rootComponent, final Component leafComponent) {
        // TODO
        return false;
    }

    private static boolean isDependencyOf(final Component leafComponent, final Component rootComponent) {
        if (leafComponent.getUuid().isBlank()) {
            // Need a UUID for our starting point.
            LOGGER.warn("%s: leaf component does not have a UUID; Unable to evaluate, returning false"
                    .formatted(FUNC_IS_DEPENDENCY_OF));
            return false;
        }

        final var compositeNodeFilter = CompositeDependencyNodeFilter.of(rootComponent);
        if (!compositeNodeFilter.hasSqlFilters()) {
            LOGGER.warn("""
                    %s: Unable to construct filter expression from root component %s; \
                    Unable to evaluate, returning false""".formatted(FUNC_IS_DEPENDENCY_OF, rootComponent));
            return false;
        }

        // TODO: Result can / should likely be cached based on filter and params.

        try (final Handle jdbiHandle = openJdbiHandle()) {
            if (!compositeNodeFilter.hasInMemoryFilters()) {
                final Query query = jdbiHandle.createQuery("""
                        -- Determine the project the given leaf component is part of.
                        WITH RECURSIVE
                        "CTE_PROJECT" AS (
                          SELECT
                            "PROJECT_ID" AS "ID"
                          FROM
                            "COMPONENT"
                          WHERE
                            "UUID" = :leafComponentUuid
                        ),
                        -- Identify the IDs of all components in the project that
                        -- match the desired criteria.
                        "CTE_MATCHES" AS (
                          SELECT
                            "ID"
                          FROM
                            "COMPONENT"
                          WHERE
                            "PROJECT_ID" = (SELECT "ID" FROM "CTE_PROJECT")
                            -- Do not consider other leaf nodes (typically the majority of components).
                            -- Because we're looking for parent nodes, they MUST have direct dependencies defined.
                            AND "DIRECT_DEPENDENCIES" IS NOT NULL
                            AND ${filters}
                        ),
                        "CTE_DEPENDENCIES" ("UUID", "PROJECT_ID", "FOUND", "PATH") AS (
                          SELECT
                            "C"."UUID"                                       AS "UUID",
                            "C"."PROJECT_ID"                                 AS "PROJECT_ID",
                            ("C"."ID" = ANY(SELECT "ID" FROM "CTE_MATCHES")) AS "FOUND",
                            ARRAY ["C"."ID"]::BIGINT[]                       AS "PATH"
                          FROM
                            "COMPONENT" AS "C"
                          WHERE
                            -- Short-circuit the recursive query if we don't have any matches at all.
                            EXISTS(SELECT 1 FROM "CTE_MATCHES")
                            AND "C"."PROJECT_ID" = (SELECT "ID" FROM "CTE_PROJECT")
                            -- Otherwise, find components of which the given leaf component is a direct dependency.
                            AND "C"."DIRECT_DEPENDENCIES" @> JSONB_BUILD_ARRAY(JSONB_BUILD_OBJECT('uuid', :leafComponentUuid))
                          UNION ALL
                          SELECT
                            "C"."UUID"                                       AS "UUID",
                            "C"."PROJECT_ID"                                 AS "PROJECT_ID",
                            ("C"."ID" = ANY(SELECT "ID" FROM "CTE_MATCHES")) AS "FOUND",
                            ARRAY_APPEND("PREVIOUS"."PATH", "C"."ID")        AS "PATH"
                          FROM
                            "COMPONENT" AS "C"
                          INNER JOIN
                            "CTE_DEPENDENCIES" AS "PREVIOUS" ON "PREVIOUS"."PROJECT_ID" = "C"."PROJECT_ID"
                          WHERE
                            -- If the previous row was a match already, we're done.
                            NOT "PREVIOUS"."FOUND"
                            -- Also, ensure we haven't seen this component before, to prevent cycles.
                            AND NOT ("C"."ID" = ANY("PREVIOUS"."PATH"))
                            -- Otherwise, the previous component must appear in the current direct dependencies.
                            AND "C"."DIRECT_DEPENDENCIES" @> JSONB_BUILD_ARRAY(JSONB_BUILD_OBJECT('uuid', "PREVIOUS"."UUID"))
                        )
                        SELECT BOOL_OR("FOUND") FROM "CTE_DEPENDENCIES";
                        """);

                return query
                        .define(ATTRIBUTE_QUERY_NAME, "%s#isDependencyOf_withoutInMemoryFilters".formatted(CelCommonPolicyLibrary.class.getSimpleName()))
                        .define("filters", compositeNodeFilter.sqlFiltersConjunctive())
                        .bind("leafComponentUuid", UUID.fromString(leafComponent.getUuid()))
                        .bindMap(compositeNodeFilter.sqlFilterParams())
                        .mapTo(Boolean.class)
                        .findOne()
                        .orElse(false);
            }

            final Query query = jdbiHandle.createQuery("""
                    -- Determine the project the given leaf component is part of.
                    WITH RECURSIVE
                    "CTE_PROJECT" AS (
                      SELECT
                        "PROJECT_ID" AS "ID"
                      FROM
                        "COMPONENT"
                      WHERE
                        "UUID" = :leafComponentUuid
                    ),
                    -- Identify the IDs of all components in the project that
                    -- match the desired criteria.
                    "CTE_MATCHES" AS (
                      SELECT
                        "ID"
                      FROM
                        "COMPONENT"
                      WHERE
                        "PROJECT_ID" = (SELECT "ID" FROM "CTE_PROJECT")
                        -- Do not consider other leaf nodes (typically the majority of components).
                        -- Because we're looking for parent nodes, they MUST have direct dependencies defined.
                        AND "DIRECT_DEPENDENCIES" IS NOT NULL
                        AND ${filters}
                    ),
                    "CTE_DEPENDENCIES" ("UUID", "PROJECT_ID", ${selectColumnNames?join(", ", "", ", ")} "FOUND", "PATH") AS (
                      SELECT
                        "C"."UUID"                                       AS "UUID",
                        "C"."PROJECT_ID"                                 AS "PROJECT_ID",
                        -- Select column required for in-memory filtering, but only if the
                        -- SQL filters already matched.
                        <#list selectColumnNames as columnName>
                        CASE
                          WHEN ("C"."ID" = ANY(SELECT "ID" FROM "CTE_MATCHES"))
                          THEN "C".${columnName}
                        END                                              AS ${columnName},
                        </#list>
                        ("C"."ID" = ANY(SELECT "ID" FROM "CTE_MATCHES")) AS "FOUND",
                        ARRAY ["C"."ID"]::BIGINT[]                       AS "PATH"
                      FROM
                        "COMPONENT" AS "C"
                      WHERE
                        -- Short-circuit the recursive query if we don't have any matches at all.
                        EXISTS(SELECT 1 FROM "CTE_MATCHES")
                        AND "C"."PROJECT_ID" = (SELECT "ID" FROM "CTE_PROJECT")
                        -- Otherwise, find components of which the given leaf component is a direct dependency.
                        AND "C"."DIRECT_DEPENDENCIES" @> JSONB_BUILD_ARRAY(JSONB_BUILD_OBJECT('uuid', :leafComponentUuid))
                      UNION ALL
                      SELECT
                        "C"."UUID"                                       AS "UUID",
                        "C"."PROJECT_ID"                                 AS "PROJECT_ID",
                        -- Select columns required for in-memory filtering, but only if the
                        -- SQL filters already matched.
                        <#list selectColumnNames as columnName>
                        CASE
                          WHEN ("C"."ID" = ANY(SELECT "ID" FROM "CTE_MATCHES"))
                          THEN "C".${columnName}
                        END                                              AS ${columnName},
                        </#list>
                        ("C"."ID" = ANY(SELECT "ID" FROM "CTE_MATCHES")) AS "FOUND",
                        ARRAY_APPEND("PREVIOUS"."PATH", "C"."ID")        AS "PATH"
                      FROM
                        "COMPONENT" AS "C"
                      INNER JOIN
                        "CTE_DEPENDENCIES" AS "PREVIOUS" ON "PREVIOUS"."PROJECT_ID" = "C"."PROJECT_ID"
                      WHERE
                        -- NB: No short-circuiting based on "PREVIOUS"."FOUND" here!
                        --     There might be more matching components on this path
                        --     for which in-memory filters need to be evaluated.
                        -- Ensure we haven't seen this component before, to prevent cycles.
                        NOT ("C"."ID" = ANY("PREVIOUS"."PATH"))
                        -- Otherwise, the previous component must appear in the current direct dependencies.
                        AND "C"."DIRECT_DEPENDENCIES" @> JSONB_BUILD_ARRAY(JSONB_BUILD_OBJECT('uuid', "PREVIOUS"."UUID"))
                    )
                    SELECT ${selectColumnNames?join(", ")} FROM "CTE_DEPENDENCIES" WHERE "FOUND";
                    """);

            return query
                    .define(ATTRIBUTE_QUERY_NAME, "%s#isDependencyOf_withInMemoryFilters".formatted(CelCommonPolicyLibrary.class.getSimpleName()))
                    .define("filters", compositeNodeFilter.sqlFiltersConjunctive())
                    .define("selectColumnNames", compositeNodeFilter.sqlSelectColumns())
                    .bind("leafComponentUuid", UUID.fromString(leafComponent.getUuid()))
                    .bindMap(compositeNodeFilter.sqlFilterParams())
                    .map(ConstructorMapper.of(DependencyNode.class))
                    .stream()
                    .anyMatch(compositeNodeFilter.inMemoryFiltersConjunctive());
        }
    }

    private static boolean isExclusiveDependencyOf(final Component leafComponent, final Component rootComponent) {
        if (leafComponent.getUuid().isBlank()) {
            // Need a UUID for our starting point.
            LOGGER.warn("%s: leaf component does not have a UUID; Unable to evaluate, returning false"
                    .formatted(FUNC_IS_EXCLUSIVE_DEPENDENCY_OF));
            return false;
        }

        final var compositeNodeFilter = CompositeDependencyNodeFilter.of(rootComponent);
        if (!compositeNodeFilter.hasSqlFilters()) {
            LOGGER.warn("""
                    %s: Unable to construct filter expression from root component %s; \
                    Unable to evaluate, returning false""".formatted(FUNC_IS_EXCLUSIVE_DEPENDENCY_OF, rootComponent));
            return false;
        }

        // TODO: Result can / should likely be cached based on filter and params.

        try (final Handle jdbiHandle = openJdbiHandle()) {
            // If the component is a direct dependency of the project,
            // it can no longer be a dependency exclusively introduced
            // through another component.
            if (isDirectDependency(jdbiHandle, leafComponent)) {
                return false;
            }

            final Query query = jdbiHandle.createQuery("""
                     -- Determine the project the given leaf component is part of.
                    WITH RECURSIVE
                    "CTE_PROJECT" AS (
                      SELECT
                        "PROJECT_ID" AS "ID"
                      FROM
                        "COMPONENT"
                      WHERE
                        "UUID" = :leafComponentUuid
                    ),
                    -- Identify the IDs of all components in the project that
                    -- match the desired criteria.
                    "CTE_MATCHES" AS (
                      SELECT
                        "ID"
                      FROM
                        "COMPONENT"
                      WHERE
                        "PROJECT_ID" = (SELECT "ID" FROM "CTE_PROJECT")
                        -- Do not consider other leaf nodes (typically the majority of components).
                        -- Because we're looking for parent nodes, they MUST have direct dependencies defined.
                        AND "DIRECT_DEPENDENCIES" IS NOT NULL
                        AND ${filters}
                    ),
                    "CTE_DEPENDENCIES" ("ID", "UUID", "PROJECT_ID", ${selectColumnNames?join(", ", "", ", ")} "FOUND", "PATH") AS (
                      SELECT
                        "C"."ID"                                         AS "ID",
                        "C"."UUID"                                       AS "UUID",
                        "C"."PROJECT_ID"                                 AS "PROJECT_ID",
                        -- Select columns required for in-memory filtering, but only if the
                        -- SQL filters already matched.
                        <#list selectColumnNames as columnName>
                        CASE
                          WHEN ("C"."ID" = ANY(SELECT "ID" FROM "CTE_MATCHES"))
                          THEN "C".${columnName}
                        END                                              AS ${columnName},
                        </#list>
                        ("C"."ID" = ANY(SELECT "ID" FROM "CTE_MATCHES")) AS "FOUND",
                        ARRAY ["C"."ID"]::BIGINT[]                       AS "PATH"
                      FROM
                        "COMPONENT" AS "C"
                      WHERE
                        -- Short-circuit the recursive query if we don't have any matches at all.
                        EXISTS(SELECT 1 FROM "CTE_MATCHES")
                        AND "C"."PROJECT_ID" = (SELECT "ID" FROM "CTE_PROJECT")
                        -- Otherwise, find components of which the given leaf component is a direct dependency.
                        AND "C"."DIRECT_DEPENDENCIES" @> JSONB_BUILD_ARRAY(JSONB_BUILD_OBJECT('uuid', :leafComponentUuid))
                      UNION ALL
                      SELECT
                        "C"."ID"                                         AS "ID",
                        "C"."UUID"                                       AS "UUID",
                        "C"."PROJECT_ID"                                 AS "PROJECT_ID",
                        -- Select columns required for in-memory filtering, but only if the
                        -- SQL filters already matched.
                        <#list selectColumnNames as columnName>
                        CASE
                          WHEN ("C"."ID" = ANY(SELECT "ID" FROM "CTE_MATCHES"))
                          THEN "C".${columnName}
                        END                                              AS ${columnName},
                        </#list>
                        ("C"."ID" = ANY(SELECT "ID" FROM "CTE_MATCHES")) AS "FOUND",
                        ARRAY_APPEND("PREVIOUS"."PATH", "C"."ID")        AS "PATH"
                      FROM
                        "COMPONENT" AS "C"
                      INNER JOIN
                        "CTE_DEPENDENCIES" AS "PREVIOUS" ON "PREVIOUS"."PROJECT_ID" = "C"."PROJECT_ID"
                      WHERE
                        -- NB: No short-circuiting based on "PREVIOUS"."FOUND" here!
                        --     There might be more matching components on this path
                        --     for which in-memory filters need to be evaluated.
                        -- Ensure we haven't seen this component before, to prevent cycles.
                        NOT ("C"."ID" = ANY("PREVIOUS"."PATH"))
                        -- Otherwise, the previous component must appear in the current direct dependencies.
                        AND "C"."DIRECT_DEPENDENCIES" @> JSONB_BUILD_ARRAY(JSONB_BUILD_OBJECT('uuid', "PREVIOUS"."UUID"))
                    )
                    SELECT "ID", ${selectColumnNames?join(", ", "", ", ")} "FOUND", "PATH" FROM "CTE_DEPENDENCIES";
                    """);

            final List<DependencyNode> nodes = query
                    .define(ATTRIBUTE_QUERY_NAME, "%s#isExclusiveDependencyOf".formatted(CelCommonPolicyLibrary.class.getSimpleName()))
                    .define("filters", compositeNodeFilter.sqlFiltersConjunctive())
                    .define("selectColumnNames", compositeNodeFilter.sqlSelectColumns())
                    .bind("leafComponentUuid", UUID.fromString(leafComponent.getUuid()))
                    .bindMap(compositeNodeFilter.sqlFilterParams())
                    .map(ConstructorMapper.of(DependencyNode.class))
                    .list();
            if (nodes.isEmpty()) {
                // No component matches the filter criteria.
                return false;
            }

            final Set<Long> matchedNodeIds = nodes.stream()
                    .filter(node -> node.found() != null && node.found())
                    .filter(compositeNodeFilter.inMemoryFiltersConjunctive())
                    .map(DependencyNode::id)
                    .collect(Collectors.toSet());
            if (matchedNodeIds.isEmpty()) {
                // None of the nodes matches the filter criteria.
                return false;
            }

            final List<List<Long>> paths = reducePaths(nodes);

            return paths.stream().allMatch(path -> path.stream().anyMatch(matchedNodeIds::contains));
        }
    }

    private static boolean matchesRange(final String version, final String versStr) {
        try {
            return Vers.parse(versStr).contains(version);
        } catch (VersException e) {
            LOGGER.warn("%s: Failed to check if version %s matches range %s"
                    .formatted(FUNC_MATCHES_RANGE, version, versStr), e);
            return false;
        }
    }

    private static boolean isComponentOld(Component component, String comparator, String age) {
        if (!component.hasPublishedAt()) {
            return false;
        }
        var componentPublishedDate = component.getPublishedAt();
        final Period agePeriod;
        try {
            agePeriod = Period.parse(age);
        } catch (DateTimeParseException e) {
            LOGGER.error("%s: Invalid age duration format \"%s\"".formatted(FUNC_COMPARE_AGE, age), e);
            return false;
        }
        if (agePeriod.isZero() || agePeriod.isNegative()) {
            LOGGER.warn("%s: Age durations must not be zero or negative, but was %s".formatted(FUNC_COMPARE_AGE, agePeriod));
            return false;
        }
        if (!component.hasPublishedAt()) {
            return false;
        }
        Instant instant = Instant.ofEpochSecond(componentPublishedDate.getSeconds(), componentPublishedDate.getNanos());
        final LocalDate publishedDate = LocalDate.ofInstant(instant, ZoneId.systemDefault());
        final LocalDate ageDate = publishedDate.plus(agePeriod);
        final LocalDate today = LocalDate.now(ZoneId.systemDefault());
        return switch (comparator) {
            case "NUMERIC_GREATER_THAN", ">" -> ageDate.isBefore(today);
            case "NUMERIC_GREATER_THAN_OR_EQUAL", ">=" -> ageDate.isEqual(today) || ageDate.isBefore(today);
            case "NUMERIC_EQUAL", "==" -> ageDate.isEqual(today);
            case "NUMERIC_NOT_EQUAL", "!=" -> !ageDate.isEqual(today);
            case "NUMERIC_LESSER_THAN_OR_EQUAL", "<=" -> ageDate.isEqual(today) || ageDate.isAfter(today);
            case "NUMERIC_LESS_THAN", "<" -> ageDate.isAfter(LocalDate.now(ZoneId.systemDefault()));
            default -> {
                LOGGER.warn("%s: Operator %s is not supported for component age conditions".formatted(FUNC_COMPARE_AGE, comparator));
                yield false;
            }
        };
    }

    public record DependencyNode(@Nullable Long id, @Nullable String version,
                                 @Nullable Boolean found, @Nullable List<Long> path) {
    }

    private record CompositeDependencyNodeFilter(List<String> sqlFilters,
                                                 Map<String, Object> sqlFilterParams,
                                                 List<String> sqlSelectColumns,
                                                 List<Predicate<DependencyNode>> inMemoryFilters) {

        private static final String VALUE_PREFIX_REGEX = "re:";
        private static final String VALUE_PREFIX_VERS = "vers:";

        private static CompositeDependencyNodeFilter of(final Component component) {
            final var sqlFilters = new ArrayList<String>();
            final var sqlFilterParams = new HashMap<String, Object>();
            final var sqlSelectColumns = new ArrayList<String>();
            final var inMemoryFilters = new ArrayList<Predicate<DependencyNode>>();

            if (!component.getUuid().isBlank()) {
                sqlFilters.add("\"UUID\" = :uuid");
                sqlFilterParams.put("uuid", component.getUuid());
            }
            if (!component.getGroup().isBlank()) {
                if (component.getGroup().startsWith(VALUE_PREFIX_REGEX)) {
                    sqlFilters.add("\"GROUP\" ~ :groupRegex");
                    sqlFilterParams.put("groupRegex", substringAfter(component.getGroup(), VALUE_PREFIX_REGEX));
                } else {
                    sqlFilters.add("\"GROUP\" = :group");
                    sqlFilterParams.put("group", component.getGroup());
                }
            }
            if (!component.getName().isBlank()) {
                if (component.getName().startsWith(VALUE_PREFIX_REGEX)) {
                    sqlFilters.add("\"NAME\" ~ :nameRegex");
                    sqlFilterParams.put("nameRegex", substringAfter(component.getName(), VALUE_PREFIX_REGEX));
                } else {
                    sqlFilters.add("\"NAME\" = :name");
                    sqlFilterParams.put("name", component.getName());
                }
            }
            if (!component.getVersion().isBlank()) {
                if (component.getVersion().startsWith(VALUE_PREFIX_REGEX)) {
                    sqlFilters.add("\"VERSION\" ~ :versionRegex");
                    sqlFilterParams.put("versionRegex", substringAfter(component.getVersion(), VALUE_PREFIX_REGEX));
                } else if (component.getVersion().startsWith(VALUE_PREFIX_VERS)) {
                    // NB: Validation already happens during script compilation.
                    final Vers vers = Vers.parse(component.getVersion());
                    inMemoryFilters.add(node -> node.version() != null && vers.contains(node.version()));
                    sqlSelectColumns.add("\"VERSION\"");
                } else {
                    sqlFilters.add("\"VERSION\" = :version");
                    sqlFilterParams.put("version", component.getVersion());
                }
            }
            if (!component.getClassifier().isBlank()) {
                sqlFilters.add("\"CLASSIFIER\" = :classifier");
                sqlFilterParams.put("classifier", component.getClassifier());
            }
            if (!component.getCpe().isBlank()) {
                if (component.getCpe().startsWith(VALUE_PREFIX_REGEX)) {
                    sqlFilters.add("\"CPE\" ~ :cpeRegex");
                    sqlFilterParams.put("cpeRegex", substringAfter(component.getCpe(), VALUE_PREFIX_REGEX));
                } else {
                    sqlFilters.add("\"CPE\" = :cpe");
                    sqlFilterParams.put("cpe", component.getCpe());
                }
            }
            if (!component.getPurl().isBlank()) {
                if (component.getPurl().startsWith(VALUE_PREFIX_REGEX)) {
                    sqlFilters.add("\"PURL\" ~ :purlRegex");
                    sqlFilterParams.put("purlRegex", substringAfter(component.getPurl(), VALUE_PREFIX_REGEX));
                } else {
                    sqlFilters.add("\"PURL\" = :purl");
                    sqlFilterParams.put("purl", component.getPurl());
                }
            }
            if (!component.getSwidTagId().isBlank()) {
                if (component.getSwidTagId().startsWith(VALUE_PREFIX_REGEX)) {
                    sqlFilters.add("\"SWIDTAGID\" ~ :swidTagIdRegex");
                    sqlFilterParams.put("swidTagIdRegex", substringAfter(component.getSwidTagId(), VALUE_PREFIX_REGEX));
                } else {
                    sqlFilters.add("\"SWIDTAGID\" = :swidTagId");
                    sqlFilterParams.put("swidTagId", component.getSwidTagId());
                }
            }
            if (component.hasIsInternal()) {
                if (component.getIsInternal()) {
                    sqlFilters.add("\"INTERNAL\" = TRUE");
                } else {
                    sqlFilters.add("(\"INTERNAL\" IS NULL OR \"INTERNAL\" = FALSE)");
                }
            }

            return new CompositeDependencyNodeFilter(sqlFilters, sqlFilterParams, sqlSelectColumns, inMemoryFilters);
        }

        private boolean hasSqlFilters() {
            return sqlFilters != null && !sqlFilters.isEmpty();
        }

        private boolean hasInMemoryFilters() {
            return inMemoryFilters != null && !inMemoryFilters.isEmpty();
        }

        private String sqlFiltersConjunctive() {
            return String.join(" AND ", sqlFilters);
        }

        private Predicate<DependencyNode> inMemoryFiltersConjunctive() {
            return inMemoryFilters.stream().reduce(Predicate::and).orElse(node -> true);
        }

    }

    /**
     * Reduce paths of all {@link DependencyNode}s to complete, unique paths.
     * e.g. [[3, 2, 1], [2, 1], [1]] reduces to [[3, 2, 1]].
     *
     * @param nodes The {@link DependencyNode}s to reduce paths for
     * @return The reduced paths
     */
    private static List<List<Long>> reducePaths(final List<DependencyNode> nodes) {
        return nodes.stream()
                .map(DependencyNode::path)
                .sorted(Collections.reverseOrder(Comparator.comparingInt(List::size)))
                .collect(
                        ArrayList::new,
                        (ArrayList<List<Long>> paths, List<Long> newPath) -> {
                            final boolean isCovered = paths.stream()
                                    .anyMatch(path -> containsExactly(path, newPath));
                            if (!isCovered) {
                                paths.add(newPath);
                            }
                        },
                        ArrayList::addAll
                );
    }

    private static <T> boolean containsExactly(final List<T> lhs, final List<T> rhs) {
        final int lhsSize = lhs.size();
        final int rhsSize = rhs.size();
        final int maxSize = Math.min(lhsSize, rhsSize);

        if (lhsSize > rhsSize) {
            return Objects.equals(lhs.subList(0, maxSize), rhs);
        } else if (lhsSize < rhsSize) {
            return Objects.equals(lhs, rhs.subList(0, maxSize));
        }

        return Objects.equals(lhs, rhs);
    }

    private static boolean isDirectDependency(final Handle jdbiHandle, final Component component) {
        final Query query = jdbiHandle.createQuery("""
                SELECT
                  1
                FROM
                  "COMPONENT" AS "C"
                INNER JOIN
                  "PROJECT" AS "P" ON "P"."ID" = "C"."PROJECT_ID"
                WHERE
                  "C"."UUID" = :leafComponentUuid
                  AND "P"."DIRECT_DEPENDENCIES" @> JSONB_BUILD_ARRAY(JSONB_BUILD_OBJECT('uuid', :leafComponentUuid))
                """);

        return query
                .define(ATTRIBUTE_QUERY_NAME, "%s#isDirectDependency".formatted(CelCommonPolicyLibrary.class.getSimpleName()))
                .bind("leafComponentUuid", UUID.fromString(component.getUuid()))
                .mapTo(Boolean.class)
                .findOne()
                .orElse(false);
    }

}
