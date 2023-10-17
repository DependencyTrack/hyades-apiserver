package org.dependencytrack.policy.cel;

import alpine.common.logging.Logger;
import com.google.api.expr.v1alpha1.Type;
import io.github.nscuro.versatile.Vers;
import io.github.nscuro.versatile.VersException;
import org.apache.commons.lang3.tuple.Pair;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.proto.policy.v1.Component;
import org.dependencytrack.proto.policy.v1.License;
import org.dependencytrack.proto.policy.v1.Project;
import org.dependencytrack.proto.policy.v1.Vulnerability;
import org.projectnessie.cel.EnvOption;
import org.projectnessie.cel.Library;
import org.projectnessie.cel.ProgramOption;
import org.projectnessie.cel.checker.Decls;
import org.projectnessie.cel.common.types.Err;
import org.projectnessie.cel.common.types.Types;
import org.projectnessie.cel.common.types.ref.Val;
import org.projectnessie.cel.interpreter.functions.Overload;

import javax.jdo.Query;
import javax.jdo.datastore.JDOConnection;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.LocalDate;
import java.time.Period;
import java.time.ZoneId;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

class CelPolicyLibrary implements Library {

    private static final Logger LOGGER = Logger.getLogger(CelPolicyLibrary.class);

    static final String VAR_COMPONENT = "component";
    static final String VAR_PROJECT = "project";
    static final String VAR_VULNERABILITIES = "vulns";

    static final Type TYPE_COMPONENT = Decls.newObjectType(Component.getDescriptor().getFullName());
    static final Type TYPE_LICENSE = Decls.newObjectType(License.getDescriptor().getFullName());
    static final Type TYPE_LICENSE_GROUP = Decls.newObjectType(License.Group.getDescriptor().getFullName());
    static final Type TYPE_PROJECT = Decls.newObjectType(Project.getDescriptor().getFullName());
    static final Type TYPE_PROJECT_PROPERTY = Decls.newObjectType(Project.Property.getDescriptor().getFullName());
    static final Type TYPE_VULNERABILITY = Decls.newObjectType(Vulnerability.getDescriptor().getFullName());
    static final Type TYPE_VULNERABILITIES = Decls.newListType(TYPE_VULNERABILITY);
    static final Type TYPE_VULNERABILITY_ALIAS = Decls.newObjectType(Vulnerability.Alias.getDescriptor().getFullName());

    static final String FUNC_DEPENDS_ON = "depends_on";
    static final String FUNC_IS_DEPENDENCY_OF = "is_dependency_of";
    static final String FUNC_MATCHES_RANGE = "matches_range";
    static final String FUNC_COMPARE_COMPONENT_AGE = "compare_component_age";

    @Override
    public List<EnvOption> getCompileOptions() {
        return List.of(
                EnvOption.declarations(
                        Decls.newVar(
                                VAR_COMPONENT,
                                TYPE_COMPONENT
                        ),
                        Decls.newVar(
                                VAR_PROJECT,
                                TYPE_PROJECT
                        ),
                        Decls.newVar(
                                VAR_VULNERABILITIES,
                                TYPE_VULNERABILITIES
                        ),
                        Decls.newFunction(
                                FUNC_DEPENDS_ON,
                                // project.depends_on(org.hyades.policy.v1.Component{name: "foo"})
                                Decls.newInstanceOverload(
                                        "project_depends_on_component_bool",
                                        List.of(TYPE_PROJECT, TYPE_COMPONENT),
                                        Decls.Bool
                                )
                        ),
                        Decls.newFunction(
                                FUNC_IS_DEPENDENCY_OF,
                                // component.is_dependency_of(org.hyades.policy.v1.Component{name: "foo"})
                                Decls.newInstanceOverload(
                                        "component_is_dependency_of_component_bool",
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
                                FUNC_COMPARE_COMPONENT_AGE,
                                Decls.newInstanceOverload(
                                        "compare_component_age_bool",
                                        List.of(TYPE_COMPONENT, Decls.String),
                                        Decls.Bool
                                )
                        )
                ),
                EnvOption.types(
                        Component.getDefaultInstance(),
                        License.getDefaultInstance(),
                        License.Group.getDefaultInstance(),
                        Project.getDefaultInstance(),
                        Project.Property.getDefaultInstance(),
                        Vulnerability.getDefaultInstance(),
                        Vulnerability.Alias.getDefaultInstance()
                )
        );
    }

    @Override
    public List<ProgramOption> getProgramOptions() {
        return List.of(
                ProgramOption.functions(
                        Overload.binary(
                                FUNC_DEPENDS_ON,
                                CelPolicyLibrary::dependsOnFunc
                        ),
                        Overload.binary(
                                FUNC_IS_DEPENDENCY_OF,
                                CelPolicyLibrary::isDependencyOfFunc
                        ),
                        Overload.binary(
                                FUNC_MATCHES_RANGE,
                                CelPolicyLibrary::matchesRangeFunc
                        ),
                        Overload.binary(FUNC_COMPARE_COMPONENT_AGE,
                                CelPolicyLibrary::isComponentOldFunc
                        )
                )
        );
    }

    private static Val dependsOnFunc(final Val lhs, final Val rhs) {
        final Component leafComponent;
        if (rhs.value() instanceof final Component rhsValue) {
            leafComponent = rhsValue;
        } else {
            return Err.maybeNoSuchOverloadErr(rhs);
        }

        if (lhs.value() instanceof final Project project) {
            // project.depends_on(org.hyades.policy.v1.Component{name: "foo"})
            return Types.boolOf(dependsOn(project, leafComponent));
        }

        return Err.maybeNoSuchOverloadErr(lhs);
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

    private static Val isComponentOldFunc(final Val lhs, final Val rhs) {
        final Component lhsValue = (Component) lhs.value();
        final String dateValue = (String) rhs.value();
        return Types.boolOf(isComponentOld(lhsValue, dateValue));
    }

    private static boolean dependsOn(final Project project, final Component component) {
        if (project.getUuid().isBlank()) {
            // Need a UUID for our starting point.
            LOGGER.warn("%s: project does not have a UUID; Unable to evaluate, returning false"
                    .formatted(FUNC_DEPENDS_ON));
            return false;
        }

        final Pair<String, Map<String, Object>> filterAndParams = toFilterAndParams(component);
        if (filterAndParams == null) {
            LOGGER.warn("""
                    %s: Unable to construct filter expression from component %s; \
                    Unable to evaluate, returning false""".formatted(FUNC_DEPENDS_ON, component));
            return false;
        }

        final String filter = "project.uuid == :projectUuid && " + filterAndParams.getLeft();
        final Map<String, Object> params = filterAndParams.getRight();
        params.put("projectUuid", UUID.fromString(project.getUuid()));

        // TODO: Result can / should likely be cached based on filter and params.

        try (final var qm = new QueryManager()) {
            final Query<org.dependencytrack.model.Component> query =
                    qm.getPersistenceManager().newQuery(org.dependencytrack.model.Component.class);
            query.setFilter(filter);
            query.setNamedParameters(params);
            query.setResult("count(this)");
            try {
                return query.executeResultUnique(Long.class) > 0;
            } finally {
                query.closeAll();
            }
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

        final var filters = new ArrayList<String>();
        final var params = new HashMap<Integer, Object>();
        var paramPosition = 1;
        if (!rootComponent.getUuid().isBlank()) {
            filters.add("\"C\".\"UUID\" = ?");
            params.put(paramPosition++, rootComponent.getUuid());
        }
        if (!rootComponent.getGroup().isBlank()) {
            filters.add("\"C\".\"GROUP\" = ?");
            params.put(paramPosition++, rootComponent.getGroup());
        }
        if (!rootComponent.getName().isBlank()) {
            filters.add("\"C\".\"NAME\" = ?");
            params.put(paramPosition++, rootComponent.getName());
        }
        if (!rootComponent.getVersion().isBlank()) {
            filters.add("\"C\".\"VERSION\" = ?");
            params.put(paramPosition++, rootComponent.getVersion());
        }
        if (!rootComponent.getPurl().isBlank()) {
            filters.add("\"C\".\"PURL\" = ?");
            params.put(paramPosition++, rootComponent.getPurl());
        }

        if (filters.isEmpty()) {
            LOGGER.warn("""
                    %s: Unable to construct filter expression from root component %s; \
                    Unable to evaluate, returning false""".formatted(FUNC_IS_DEPENDENCY_OF, rootComponent));
            return false;
        }

        final String sqlFilter = String.join(" AND ", filters);

        final var query = """
                WITH RECURSIVE
                "CTE_DEPENDENCIES" ("UUID", "PROJECT_ID", "FOUND", "COMPONENTS_SEEN") AS (
                  SELECT
                    "C"."UUID",
                    "C"."PROJECT_ID",
                    CASE WHEN (%s) THEN TRUE ELSE FALSE END AS "FOUND",
                    ARRAY []::BIGINT[] AS "COMPONENTS_SEEN"
                  FROM
                    "COMPONENT" AS "C"
                    WHERE
                      -- TODO: Need to get project ID from somewhere to speed up
                      --   this initial query for the CTE.
                      -- "PROJECT_ID" = ?
                        "C"."DIRECT_DEPENDENCIES" IS NOT NULL
                        AND "C"."DIRECT_DEPENDENCIES" LIKE ?
                  UNION ALL
                  SELECT
                    "C"."UUID"       AS "UUID",
                    "C"."PROJECT_ID" AS "PROJECT_ID",
                    CASE WHEN (%s) THEN TRUE ELSE FALSE END AS "FOUND",
                    ARRAY_APPEND("COMPONENTS_SEEN", "C"."ID")
                  FROM
                    "COMPONENT" AS "C"
                  INNER JOIN
                    "CTE_DEPENDENCIES"
                      ON "C"."PROJECT_ID" = "CTE_DEPENDENCIES"."PROJECT_ID"
                        AND "C"."DIRECT_DEPENDENCIES" LIKE ('%%"' || "CTE_DEPENDENCIES"."UUID" || '"%%')
                  WHERE
                    "C"."PROJECT_ID" = "CTE_DEPENDENCIES"."PROJECT_ID"
                    AND (
                      "FOUND" OR "C"."DIRECT_DEPENDENCIES" IS NOT NULL
                    )
                )
                SELECT BOOL_OR("FOUND") FROM "CTE_DEPENDENCIES";
                """.formatted(sqlFilter, sqlFilter);

        try (final var qm = new QueryManager()) {
            final JDOConnection jdoConnection = qm.getPersistenceManager().getDataStoreConnection();
            try {
                final var connection = (Connection) jdoConnection.getNativeConnection();
                final var preparedStatement = connection.prepareStatement(query);
                // Params need to be set twice because the rootComponent filter
                // appears twice in the query... This needs improvement.
                for (final Map.Entry<Integer, Object> param : params.entrySet()) {
                    preparedStatement.setObject(param.getKey(), param.getValue());
                }
                preparedStatement.setString(params.size() + 1, "%" + leafComponent.getUuid() + "%");
                for (final Map.Entry<Integer, Object> param : params.entrySet()) {
                    preparedStatement.setObject((params.size() + 1) + param.getKey(), param.getValue());
                }

                try (final ResultSet rs = preparedStatement.executeQuery()) {
                    if (rs.next()) {
                        return rs.getBoolean(1);
                    }
                }
            } catch (SQLException e) {
                LOGGER.warn("%s: Failed to execute query: %s".formatted(FUNC_IS_DEPENDENCY_OF, query), e);
            } finally {
                jdoConnection.close();
            }
        }

        return false;
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

    private static boolean isComponentOld(Component component, String rhs) {
        String comparator = null;
        String operand = null;
        if (rhs.contains("==")) {
            comparator = "==";
            operand = rhs.split("==")[1];
        }

        var componentPublishedDate = component.getCurrentVersionLastModified();
        final Period agePeriod;
        try {
            agePeriod = Period.parse(operand);
        } catch (DateTimeParseException e) {
            LOGGER.error("Invalid age duration format", e);
            return false;
        }
        if (agePeriod.isZero() || agePeriod.isNegative()) {
            LOGGER.warn("Age durations must not be zero or negative");
            return false;
        }
        Instant instant = Instant.ofEpochSecond(componentPublishedDate.getSeconds(), componentPublishedDate.getNanos());
        final LocalDate publishedDate = LocalDate.ofInstant(instant, ZoneId.systemDefault());
        final LocalDate ageDate = publishedDate.plus(agePeriod);
        final LocalDate today = LocalDate.now(ZoneId.systemDefault());
        if(comparator.equals("==")) {
            return ageDate.isEqual(today);
        }
        return false;
    }

    private static Pair<String, Map<String, Object>> toFilterAndParams(final Component component) {
        var filters = new ArrayList<String>();
        var params = new HashMap<String, Object>();

        if (!component.getUuid().isBlank()) {
            filters.add("uuid == :uuid");
            params.put("uuid", component.getUuid());
        }
        if (!component.getGroup().isBlank()) {
            filters.add("group == :group");
            params.put("group", component.getGroup());
        }
        if (!component.getName().isBlank()) {
            filters.add("name == :name");
            params.put("name", component.getName());
        }
        if (!component.getVersion().isBlank()) {
            filters.add("version");
            params.put("version", component.getVersion());
        }

        // TODO: Add more fields

        if (filters.isEmpty()) {
            return null;
        }

        return Pair.of(String.join(" && ", filters), params);
    }

}
