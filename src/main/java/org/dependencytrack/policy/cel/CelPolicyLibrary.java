package org.dependencytrack.policy.cel;

import com.google.api.expr.v1alpha1.Type;
import io.github.nscuro.versatile.Vers;
import io.github.nscuro.versatile.VersException;
import org.apache.commons.lang3.tuple.Pair;
import org.dependencytrack.persistence.QueryManager;
import org.hyades.proto.policy.v1.Component;
import org.hyades.proto.policy.v1.License;
import org.hyades.proto.policy.v1.Project;
import org.hyades.proto.policy.v1.Vulnerability;
import org.projectnessie.cel.EnvOption;
import org.projectnessie.cel.Library;
import org.projectnessie.cel.ProgramOption;
import org.projectnessie.cel.checker.Decls;
import org.projectnessie.cel.common.types.Err;
import org.projectnessie.cel.common.types.Types;
import org.projectnessie.cel.interpreter.functions.Overload;

import javax.jdo.Query;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public class CelPolicyLibrary implements Library {

    static final String VAR_COMPONENT = "component";
    static final String VAR_PROJECT = "project";
    static final String VAR_VULNERABILITIES = "vulns";

    private static final Type TYPE_COMPONENT = Decls.newObjectType(Component.getDescriptor().getFullName());
    private static final Type TYPE_PROJECT = Decls.newObjectType(Project.getDescriptor().getFullName());
    private static final Type TYPE_VULNERABILITY = Decls.newObjectType(Vulnerability.getDescriptor().getFullName());
    private static final Type TYPE_VULNERABILITIES = Decls.newListType(TYPE_VULNERABILITY);

    private static final String FUNC_DEPENDS_ON = "depends_on";
    private static final String FUNC_IS_DEPENDENCY_OF = "is_dependency_of";
    private static final String FUNC_MATCHES_RANGE = "matches_range";

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
                                // component.depends_on(org.hyades.policy.v1.Component{"name": "foo"})
                                Decls.newInstanceOverload(
                                        "component_depends_on_component_bool",
                                        List.of(TYPE_COMPONENT, TYPE_COMPONENT),
                                        Decls.Bool
                                ),
                                // project.depends_on(org.hyades.policy.v1.Component{"name": "foo"})
                                Decls.newInstanceOverload(
                                        "project_depends_on_component_bool",
                                        List.of(TYPE_PROJECT, TYPE_COMPONENT),
                                        Decls.Bool
                                )
                        ),
                        Decls.newFunction(
                                FUNC_IS_DEPENDENCY_OF,
                                // component.is_dependency_of(org.hyades.policy.v1.Component{"name": "foo"})
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
                        )
                ),
                EnvOption.types(
                        Component.getDefaultInstance(),
                        License.getDefaultInstance(),
                        Project.getDefaultInstance(),
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
                                (lhs, rhs) -> {
                                    final Component leafComponent;
                                    if (rhs.value() instanceof final Component rhsValue) {
                                        leafComponent = rhsValue;
                                    } else {
                                        return Err.maybeNoSuchOverloadErr(rhs);
                                    }

                                    if (lhs.value() instanceof final Project project) {
                                        return Types.boolOf(dependsOn(project, leafComponent));
                                    } else if (lhs.value() instanceof final Component rootComponent) {
                                        // TODO: Traverse dep graph from rootComponent downwards and look for leafComponent
                                        return Types.boolOf(dependsOn(rootComponent, leafComponent));
                                    }

                                    return Err.maybeNoSuchOverloadErr(lhs);
                                }
                        ),
                        Overload.binary(
                                FUNC_IS_DEPENDENCY_OF,
                                (lhs, rhs) -> {
                                    final Component leafComponent;
                                    if (lhs.value() instanceof final Component lhsValue) {
                                        leafComponent = lhsValue;
                                    } else {
                                        return Err.maybeNoSuchOverloadErr(lhs);
                                    }

                                    if (rhs.value() instanceof final Component rootComponent) {
                                        // TODO: traverse dep graph from lhsComponent upwards and look for rhsComponent
                                        return Types.boolOf(isDependencyOf(leafComponent, rootComponent));
                                    }

                                    return Err.maybeNoSuchOverloadErr(rhs);
                                }
                        ),
                        Overload.binary(
                                FUNC_MATCHES_RANGE,
                                (lhs, rhs) -> {
                                    final String version;
                                    if (lhs.value() instanceof final Component lhsValue) {
                                        version = lhsValue.getVersion();
                                    } else if (lhs.value() instanceof final Project lhsValue) {
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
                        )
                )
        );
    }

    private static boolean dependsOn(final Project project, final Component component) {
        if (project.getUuid().isBlank()) {
            // Need a UUID for our starting point.
            return false;
        }

        final Pair<String, Map<String, Object>> filterAndParams = toFilterAndParams(component);
        if (filterAndParams == null) {
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
            return false;
        }

        // TODO

        return false;
    }

    private static boolean matchesRange(final String version, final String versStr) {
        try {
            return Vers.parse(versStr).contains(version);
        } catch (VersException e) {
            return false;
        }
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
