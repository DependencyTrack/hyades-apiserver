package org.dependencytrack.policy.cel;

import alpine.common.logging.Logger;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import com.google.api.expr.v1alpha1.Type;
import io.github.nscuro.versatile.Vers;
import io.github.nscuro.versatile.VersException;
import org.apache.commons.lang3.tuple.Pair;
import org.dependencytrack.model.Classifier;
import org.dependencytrack.model.RepositoryType;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.proto.policy.v1.Component;
import org.dependencytrack.proto.policy.v1.License;
import org.dependencytrack.proto.policy.v1.Project;
import org.dependencytrack.proto.policy.v1.Vulnerability;
import org.dependencytrack.util.VersionDistance;
import org.projectnessie.cel.EnvOption;
import org.projectnessie.cel.Library;
import org.projectnessie.cel.ProgramOption;
import org.projectnessie.cel.checker.Decls;
import org.projectnessie.cel.common.types.BoolT;
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
    static final String VAR_NOW = "now";
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
    static final String FUNC_COMPARE_AGE = "compare_age";
    static final String FUNC_COMPARE_VERSION_DISTANCE = "version_distance";

    @Override
    public List<EnvOption> getCompileOptions() {
        return List.of(
                EnvOption.declarations(
                        Decls.newVar(
                                VAR_COMPONENT,
                                TYPE_COMPONENT
                        ),
                        Decls.newVar(
                                VAR_NOW,
                                Decls.Timestamp
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
                                // project.depends_on(org.dependencytrack.policy.v1.Component{name: "foo"})
                                Decls.newInstanceOverload(
                                        "project_depends_on_component_bool",
                                        List.of(TYPE_PROJECT, TYPE_COMPONENT),
                                        Decls.Bool
                                )
                        ),
                        Decls.newFunction(
                                FUNC_IS_DEPENDENCY_OF,
                                // component.is_dependency_of(org.dependencytrack.policy.v1.Component{name: "foo"})
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
                                        List.of(TYPE_COMPONENT, Decls.String, Decls.String),
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
                        Overload.function(FUNC_COMPARE_AGE,
                                CelPolicyLibrary::isComponentOldFunc),
                        Overload.function(FUNC_COMPARE_VERSION_DISTANCE,
                                CelPolicyLibrary::matchesVersionDistanceFunc)
                )
        );
    }

    private static Val matchesVersionDistanceFunc(Val... vals) {
        var basicCheckResult = basicCheck(vals);
        if ((basicCheckResult instanceof BoolT && basicCheckResult.value() == Types.boolOf(false)) || basicCheckResult instanceof Err) {
            return basicCheckResult;
        }
        var component = (Component) vals[0].value();
        var value = (String) vals[2].value();
        var comparator = (String) vals[1].value();
        if (!component.hasLatestVersion()) {
            return Err.newErr("Requested component does not have latest version information", component);
        }
        return Types.boolOf(matchesVersionDistance(component, comparator, value));
    }

    private static boolean matchesVersionDistance(Component component, String comparator, String value) {
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
        final VersionDistance versionDistance;
        try {
            versionDistance = VersionDistance.getVersionDistance(component.getVersion(), component.getLatestVersion());
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
        return isDirectDependency && VersionDistance.evaluate(value, comparatorComputed, versionDistance);
    }

    private static Val dependsOnFunc(final Val lhs, final Val rhs) {
        final Component leafComponent;
        if (rhs.value() instanceof final Component rhsValue) {
            leafComponent = rhsValue;
        } else {
            return Err.maybeNoSuchOverloadErr(rhs);
        }

        if (lhs.value() instanceof final Project project) {
            // project.depends_on(org.dependencytrack.policy.v1.Component{name: "foo"})
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

    private static Val basicCheck(Val... vals) {
        if (vals.length != 3) {
            return Types.boolOf(false);
        }
        if (vals[0].value() == null || vals[1].value() == null || vals[2].value() == null) {
            return Types.boolOf(false);
        }

        if (!(vals[0].value() instanceof final Component component)) {
            return Err.maybeNoSuchOverloadErr(vals[0]);
        }
        if (!(vals[1].value() instanceof String)) {
            return Err.maybeNoSuchOverloadErr(vals[1]);
        }

        if (!(vals[2].value() instanceof String)) {
            return Err.maybeNoSuchOverloadErr(vals[2]);
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
        if (!rootComponent.getClassifier().isBlank()) {
            filters.add("\"C\".\"CLASSIFIER\" = ?");
            params.put(paramPosition++, rootComponent.getClassifier());
        }
        if (!rootComponent.getCpe().isBlank()) {
            filters.add("\"C\".\"CPE\" = ?");
            params.put(paramPosition++, rootComponent.getCpe());
        }
        if (!rootComponent.getPurl().isBlank()) {
            filters.add("\"C\".\"PURL\" = ?");
            params.put(paramPosition++, rootComponent.getPurl());
        }
        if (!rootComponent.getSwidTagId().isBlank()) {
            filters.add("\"C\".\"SWIDTAGID\" = ?");
            params.put(paramPosition++, rootComponent.getSwidTagId());
        }
        if (rootComponent.hasIsInternal()) {
            if (rootComponent.getIsInternal()) {
                filters.add("\"C\".\"INTERNAL\" = ?");
                params.put(paramPosition++, true);
            } else {
                filters.add("(\"C\".\"INTERNAL\" IS NULL OR \"C\".\"INTERNAL\" = ?)");
                params.put(paramPosition++, false);
            }
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
            filters.add("version == :version");
            params.put("version", component.getVersion());
        }
        if (!component.getClassifier().isBlank()) {
            try {
                filters.add("classifier == :classifier");
                params.put("classifier", Classifier.valueOf(component.getClassifier()));
            } catch (IllegalArgumentException e) {
                LOGGER.warn("\"%s\" is not a valid classifier; Skipping".formatted(component.getClassifier()), e);
            }
        }
        if (!component.getCpe().isBlank()) {
            filters.add("cpe == :cpe");
            params.put("cpe", component.getCpe());
        }
        if (!component.getPurl().isBlank()) {
            filters.add("purl == :purl");
            params.put("purl", component.getPurl());
        }
        if (!component.getSwidTagId().isBlank()) {
            filters.add("swidTagId == :swidTagId");
            params.put("swidTagId", component.getSwidTagId());
        }
        if (component.hasIsInternal()) {
            if (component.getIsInternal()) {
                filters.add("internal");
            } else {
                filters.add("(internal == null || !internal)");
            }
        }

        // TODO: Add more fields

        if (filters.isEmpty()) {
            return null;
        }

        return Pair.of(String.join(" && ", filters), params);
    }
}
