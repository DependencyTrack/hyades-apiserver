package org.dependencytrack.policy.cel;

import alpine.common.logging.Logger;
import alpine.common.metrics.Metrics;
import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.github.packageurl.PackageURL;
import com.google.api.expr.v1alpha1.Type;
import com.google.protobuf.util.Timestamps;
import io.micrometer.core.instrument.Timer;
import org.apache.commons.collections4.MultiValuedMap;
import org.apache.commons.collections4.multimap.HashSetValuedHashMap;
import org.apache.commons.lang3.tuple.Pair;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.LicenseGroup;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.PolicyCondition.Subject;
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Tag;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.policy.cel.compat.CelPolicyScriptSourceBuilder;
import org.dependencytrack.policy.cel.compat.ComponentHashCelPolicyScriptSourceBuilder;
import org.dependencytrack.policy.cel.compat.CoordinatesCelPolicyScriptSourceBuilder;
import org.dependencytrack.policy.cel.compat.CpeCelPolicyScriptSourceBuilder;
import org.dependencytrack.policy.cel.compat.CweCelPolicyScriptSourceBuilder;
import org.dependencytrack.policy.cel.compat.LicenseCelPolicyScriptSourceBuilder;
import org.dependencytrack.policy.cel.compat.LicenseGroupCelPolicyScriptSourceBuilder;
import org.dependencytrack.policy.cel.compat.PackageUrlCelPolicyScriptSourceBuilder;
import org.dependencytrack.policy.cel.compat.SeverityCelPolicyScriptSourceBuilder;
import org.dependencytrack.policy.cel.compat.SwidTagIdCelPolicyScriptSourceBuilder;
import org.dependencytrack.policy.cel.compat.VulnerabilityIdCelPolicyScriptSourceBuilder;
import org.dependencytrack.policy.cel.persistence.ComponentProjection;
import org.dependencytrack.policy.cel.persistence.ComponentsVulnerabilitiesProjection;
import org.dependencytrack.policy.cel.persistence.LicenseGroupProjection;
import org.dependencytrack.policy.cel.persistence.LicenseProjection;
import org.dependencytrack.policy.cel.persistence.ProjectProjection;
import org.dependencytrack.policy.cel.persistence.VulnerabilityProjection;
import org.dependencytrack.util.NotificationUtil;
import org.dependencytrack.util.VulnerabilityUtil;
import org.hyades.proto.policy.v1.License;
import org.hyades.proto.policy.v1.Vulnerability;
import org.projectnessie.cel.tools.ScriptCreateException;
import org.projectnessie.cel.tools.ScriptException;

import javax.jdo.Query;
import javax.jdo.Transaction;
import java.math.BigDecimal;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static java.util.Collections.emptyList;
import static org.apache.commons.lang3.StringUtils.trimToEmpty;
import static org.dependencytrack.policy.cel.CelPolicyLibrary.TYPE_COMPONENT;
import static org.dependencytrack.policy.cel.CelPolicyLibrary.TYPE_LICENSE;
import static org.dependencytrack.policy.cel.CelPolicyLibrary.TYPE_LICENSE_GROUP;
import static org.dependencytrack.policy.cel.CelPolicyLibrary.TYPE_PROJECT;
import static org.dependencytrack.policy.cel.CelPolicyLibrary.TYPE_PROJECT_PROPERTY;
import static org.dependencytrack.policy.cel.CelPolicyLibrary.TYPE_VULNERABILITY;
import static org.dependencytrack.policy.cel.CelPolicyLibrary.TYPE_VULNERABILITY_ALIAS;
import static org.dependencytrack.policy.cel.CelPolicyLibrary.VAR_COMPONENT;
import static org.dependencytrack.policy.cel.CelPolicyLibrary.VAR_PROJECT;
import static org.dependencytrack.policy.cel.CelPolicyLibrary.VAR_VULNERABILITIES;
import static org.dependencytrack.policy.cel.persistence.FieldMappingUtil.getFieldMappings;

public class CelPolicyEngine {

    private static final Logger LOGGER = Logger.getLogger(CelPolicyEngine.class);
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final Map<Subject, CelPolicyScriptSourceBuilder> SCRIPT_BUILDERS;

    static {
        SCRIPT_BUILDERS = new HashMap<>();
        SCRIPT_BUILDERS.put(Subject.CPE, new CpeCelPolicyScriptSourceBuilder());
        SCRIPT_BUILDERS.put(Subject.COMPONENT_HASH, new ComponentHashCelPolicyScriptSourceBuilder());
        SCRIPT_BUILDERS.put(Subject.COORDINATES, new CoordinatesCelPolicyScriptSourceBuilder());
        SCRIPT_BUILDERS.put(Subject.CWE, new CweCelPolicyScriptSourceBuilder());
        SCRIPT_BUILDERS.put(Subject.EXPRESSION, PolicyCondition::getValue);
        SCRIPT_BUILDERS.put(Subject.LICENSE, new LicenseCelPolicyScriptSourceBuilder());
        SCRIPT_BUILDERS.put(Subject.LICENSE_GROUP, new LicenseGroupCelPolicyScriptSourceBuilder());
        SCRIPT_BUILDERS.put(Subject.PACKAGE_URL, new PackageUrlCelPolicyScriptSourceBuilder());
        SCRIPT_BUILDERS.put(Subject.SEVERITY, new SeverityCelPolicyScriptSourceBuilder());
        SCRIPT_BUILDERS.put(Subject.SWID_TAGID, new SwidTagIdCelPolicyScriptSourceBuilder());
        SCRIPT_BUILDERS.put(Subject.VULNERABILITY_ID, new VulnerabilityIdCelPolicyScriptSourceBuilder());
    }

    private final CelPolicyScriptHost scriptHost;

    public CelPolicyEngine() {
        this(CelPolicyScriptHost.getInstance());
    }

    CelPolicyEngine(final CelPolicyScriptHost scriptHost) {
        this.scriptHost = scriptHost;
    }

    public void evaluateProject(final UUID uuid) {
        final Timer.Sample timerSample = Timer.start();

        try (final var qm = new QueryManager()) {
            final Project project = qm.getObjectByUuid(Project.class, uuid, List.of(Project.FetchGroup.IDENTIFIERS.name()));
            if (project == null) {
                LOGGER.warn("Project with UUID %s does not exist".formatted(uuid));
                return;
            }

            final List<Policy> policies = getApplicablePolicies(qm, project);
            if (policies.isEmpty()) {
                // With no applicable policies, there's no way to resolve violations.
                // As a compensation, simply delete all violations associated with the component.
                LOGGER.info("No applicable policies found for component %s".formatted(uuid));
                // reconcileViolations(qm, component, Collections.emptyList());
                return;
            }

            LOGGER.info("Compiling policy scripts for project %s".formatted(uuid));
            final List<Pair<PolicyCondition, CelPolicyScript>> conditionScriptPairs = policies.stream()
                    .map(Policy::getPolicyConditions)
                    .flatMap(Collection::stream)
                    .map(policyCondition -> {
                        final CelPolicyScriptSourceBuilder scriptBuilder = SCRIPT_BUILDERS.get(policyCondition.getSubject());
                        if (scriptBuilder == null) {
                            LOGGER.warn("No script builder found that is capable of handling subjects of type %s".formatted(policyCondition.getSubject()));
                            return null;
                        }

                        final String scriptSrc = scriptBuilder.apply(policyCondition);
                        if (scriptSrc == null) {
                            LOGGER.warn("Script builder was unable to create a script for condition %s".formatted(policyCondition.getUuid()));
                            return null;
                        }

                        return Pair.of(policyCondition, scriptSrc);
                    })
                    .filter(Objects::nonNull)
                    .map(conditionScriptSrcPair -> {
                        final CelPolicyScript script;
                        try {
                            script = scriptHost.compile(conditionScriptSrcPair.getRight());
                        } catch (ScriptCreateException e) {
                            throw new RuntimeException(e);
                        }

                        return Pair.of(conditionScriptSrcPair.getLeft(), script);
                    })
                    .toList();

            LOGGER.info("Determining evaluation requirements for project %s and %d policy conditions"
                    .formatted(uuid, conditionScriptPairs.size()));
            final MultiValuedMap<Type, String> requirements = conditionScriptPairs.stream()
                    .map(Pair::getRight)
                    .map(CelPolicyScript::getRequirements)
                    .reduce(new HashSetValuedHashMap<>(), (a, b) -> {
                        a.putAll(b);
                        return a;
                    });
            LOGGER.info("Requirements for project %s and %d policy conditions: %s"
                    .formatted(uuid, conditionScriptPairs.size(), requirements));

            final org.hyades.proto.policy.v1.Project protoProject;
            if (requirements.containsKey(TYPE_PROJECT)) {
                protoProject = mapProject(fetchProject(qm, project.getId(), requirements.get(TYPE_PROJECT)));
            } else {
                protoProject = org.hyades.proto.policy.v1.Project.getDefaultInstance();
            }

            // Preload components for the entire project, to avoid excessive queries.
            final List<ComponentProjection> components = fetchComponents(qm, project.getId(), requirements.get(TYPE_COMPONENT));

            // Preload licenses for the entire project, as chances are high that they will be used by multiple components.
            final Map<Long, License> licenseById;
            if (requirements.containsKey(TYPE_LICENSE)) {
                licenseById = fetchLicenses(qm, project.getId(), requirements.get(TYPE_LICENSE), requirements.get(TYPE_LICENSE_GROUP)).stream()
                        .map(projection -> Pair.of(projection.id, mapLicense(projection)))
                        .collect(Collectors.toMap(Pair::getLeft, Pair::getRight));
            } else {
                licenseById = Collections.emptyMap();
            }

            // Preload vulnerabilities for the entire project, as chances are high that they will be used by multiple components.
            final Map<Long, Vulnerability> protoVulnById;
            final Map<Long, List<Long>> vulnIdsByComponentId;
            if (requirements.containsKey(TYPE_VULNERABILITY)) {
                protoVulnById = fetchVulnerabilities(qm, project.getId(), requirements.get(TYPE_VULNERABILITY)).stream()
                        .map(vulnProjection -> Pair.of(vulnProjection.id, Vulnerability.getDefaultInstance()))
                        .collect(Collectors.toMap(Pair::getLeft, Pair::getRight));

                vulnIdsByComponentId = fetchComponentsVulnerabilities(qm, project.getId()).stream()
                        .collect(Collectors.groupingBy(
                                projection -> projection.componentId,
                                Collectors.mapping(projection -> projection.vulnerabilityId, Collectors.toList())
                        ));
            } else {
                protoVulnById = Collections.emptyMap();
                vulnIdsByComponentId = Collections.emptyMap();
            }

            final var conditionsViolated = new HashSetValuedHashMap<Long, PolicyCondition>();
            for (final ComponentProjection component : components) {
                final org.hyades.proto.policy.v1.Component protoComponent = mapComponent(component, licenseById);

                final List<Vulnerability> vulns = vulnIdsByComponentId.getOrDefault(component.id, emptyList()).stream()
                        .map(protoVulnById::get)
                        .toList();

                for (final Pair<PolicyCondition, CelPolicyScript> conditionScriptPair : conditionScriptPairs) {
                    final PolicyCondition condition = conditionScriptPair.getLeft();
                    final CelPolicyScript script = conditionScriptPair.getRight();
                    final Map<String, Object> scriptArgs = Map.of(
                            VAR_COMPONENT, protoComponent,
                            VAR_PROJECT, protoProject,
                            VAR_VULNERABILITIES, vulns
                    );

                    try {
                        if (script.execute(scriptArgs)) {
                            conditionsViolated.put(component.id, condition);
                        }
                    } catch (ScriptException e) {
                        throw new RuntimeException("Failed to evaluate script", e);
                    }
                }

                if (!conditionsViolated.containsKey(component.id)) {
                    conditionsViolated.putAll(component.id, Collections.emptySet());
                }
            }

            // In order to create policy violations, we need Component objects that are attached to the
            // persistence context.
            final Query<Component> componentQuery = qm.getPersistenceManager().newQuery(Component.class);
            componentQuery.getFetchPlan().setGroup(Component.FetchGroup.IDENTITY.name());
            componentQuery.setFilter(":ids.contains(id)");
            componentQuery.setParameters(conditionsViolated.keySet());
            final Map<Long, Component> persistentComponentById;
            try {
                persistentComponentById = componentQuery.executeList().stream()
                        .collect(Collectors.toMap(Component::getId, Function.identity()));
            } finally {
                componentQuery.closeAll();
            }

            // TODO: Short-circuit for components for which no violations were detected.

            for (final long componentId : conditionsViolated.keySet()) {
                final Map<Policy, List<PolicyCondition>> violatedConditionsByPolicy = conditionsViolated.get(componentId).stream()
                        .collect(Collectors.groupingBy(PolicyCondition::getPolicy));

                final List<PolicyViolation> violations = violatedConditionsByPolicy.entrySet().stream()
                        .flatMap(policyAndViolatedConditions -> {
                            final Policy policy = policyAndViolatedConditions.getKey();
                            final List<PolicyCondition> violatedConditions = policyAndViolatedConditions.getValue();

                            if ((policy.getOperator() == Policy.Operator.ANY && !violatedConditions.isEmpty())
                                    || (policy.getOperator() == Policy.Operator.ALL && violatedConditions.size() == policy.getPolicyConditions().size())) {
                                // TODO: Only a single violation should be raised, and instead multiple matched conditions
                                //   should be associated with it. Keeping the existing behavior in order to avoid having to
                                //   touch too much persistence and REST API code.
                                return violatedConditions.stream()
                                        .map(condition -> {
                                            final var violation = new PolicyViolation();
                                            violation.setComponent(persistentComponentById.get(componentId));
                                            violation.setType(condition.getViolationType());
                                            violation.setPolicyCondition(condition);
                                            violation.setTimestamp(new Date());
                                            return violation;
                                        });
                            }

                            return Stream.empty();
                        })
                        .filter(Objects::nonNull)
                        .toList();

                final List<PolicyViolation> newViolations = reconcileViolations(qm, persistentComponentById.get(componentId), violations);
            }
        } finally {
            final long durationNs = timerSample.stop(Timer
                    .builder("dtrack_policy_eval")
                    .tag("target", "project")
                    .register(Metrics.getRegistry()));
            LOGGER.info("Evaluation of project %s completed in %s"
                    .formatted(uuid, Duration.ofNanos(durationNs)));
        }
    }

    // TODO: Just here to satisfy contract with legacy PolicyEngine; Remove after testing
    public void evaluate(final List<Component> components) {
        components.stream().map(Component::getUuid).forEach(this::evaluateComponent);
    }

    public void evaluateComponent(final UUID componentUuid) {
        final Timer.Sample timerSample = Timer.start();

        try (final var qm = new QueryManager()) {
            final Component component = qm.getObjectByUuid(Component.class, componentUuid);
            if (component == null) {
                LOGGER.warn("Component with UUID %s does not exist".formatted(componentUuid));
                return;
            }

            final List<Policy> policies = getApplicablePolicies(qm, component.getProject());
            if (policies.isEmpty()) {
                // With no applicable policies, there's no way to resolve violations.
                // As a compensation, simply delete all violations associated with the component.
                LOGGER.info("No applicable policies found for component %s".formatted(componentUuid));
                reconcileViolations(qm, component, emptyList());
                return;
            }

            // Pre-compile the CEL scripts for all conditions of all applicable policies.
            // Compiled scripts are cached in-memory by CelPolicyScriptHost, so if the same script
            // is encountered for multiple components (possibly concurrently), the compilation is
            // a one-time effort.
            LOGGER.info("Compiling policy scripts for component %s".formatted(componentUuid));
            final List<Pair<PolicyCondition, CelPolicyScript>> conditionScriptPairs = policies.stream()
                    .map(Policy::getPolicyConditions)
                    .flatMap(Collection::stream)
                    .map(policyCondition -> {
                        final CelPolicyScriptSourceBuilder scriptBuilder = SCRIPT_BUILDERS.get(policyCondition.getSubject());
                        if (scriptBuilder == null) {
                            LOGGER.warn("No script builder found that is capable of handling subjects of type %s".formatted(policyCondition.getSubject()));
                            return null;
                        }

                        final String scriptSrc = scriptBuilder.apply(policyCondition);
                        if (scriptSrc == null) {
                            LOGGER.warn("Script builder was unable to create a script for condition %s".formatted(policyCondition.getUuid()));
                            return null;
                        }

                        return Pair.of(policyCondition, scriptSrc);
                    })
                    .filter(Objects::nonNull)
                    .map(conditionScriptSrcPair -> {
                        final CelPolicyScript script;
                        try {
                            script = scriptHost.compile(conditionScriptSrcPair.getRight());
                        } catch (ScriptCreateException e) {
                            throw new RuntimeException(e);
                        }

                        return Pair.of(conditionScriptSrcPair.getLeft(), script);
                    })
                    .toList();

            // Check what kind of data we need to evaluate all policy conditions.
            //
            // Some conditions will be very simple and won't require us to load additional data (e.g. "component PURL matches 'XYZ'"),
            // whereas other conditions can span across multiple models, forcing us to load more data
            // (e.g. "project has tag 'public-facing' and component has a vulnerability with severity 'critical'").
            //
            // What we want to avoid is loading data we don't need, and loading it multiple times.
            // Instead, only load what's really needed, and only do so once.
            LOGGER.info("Determining evaluation requirements for component %s and %d policy conditions"
                    .formatted(componentUuid, conditionScriptPairs.size()));
            final MultiValuedMap<Type, String> requirements = conditionScriptPairs.stream()
                    .map(Pair::getRight)
                    .map(CelPolicyScript::getRequirements)
                    .reduce(new HashSetValuedHashMap<>(), (a, b) -> {
                        a.putAll(b);
                        return a;
                    });

            // Prepare the script arguments according to the requirements gathered before.
            LOGGER.info("Building script arguments for component %s and requirements %s"
                    .formatted(componentUuid, requirements));
            final Map<String, Object> scriptArgs = Map.of(
                    VAR_COMPONENT, mapComponent(qm, component, requirements),
                    VAR_PROJECT, mapProject(component.getProject(), requirements),
                    VAR_VULNERABILITIES, loadVulnerabilities(qm, component, requirements)
            );

            LOGGER.info("Evaluating component %s against %d applicable policy conditions"
                    .formatted(componentUuid, conditionScriptPairs.size()));
            final var conditionsViolated = new HashSet<PolicyCondition>();
            for (final Pair<PolicyCondition, CelPolicyScript> conditionScriptPair : conditionScriptPairs) {
                final PolicyCondition condition = conditionScriptPair.getLeft();
                final CelPolicyScript script = conditionScriptPair.getRight();
                LOGGER.info("Executing script for policy condition %s with arguments: %s"
                        .formatted(condition.getUuid(), scriptArgs));

                try {
                    if (script.execute(scriptArgs)) {
                        conditionsViolated.add(condition);
                    }
                } catch (ScriptException e) {
                    throw new RuntimeException("Failed to evaluate script", e);
                }
            }

            // Group the detected condition violations by policy. Necessary to be able to evaluate
            // each policy's operator (ANY, ALL).
            LOGGER.info("Detected violation of %d policy conditions for component %s; Evaluating policy operators"
                    .formatted(conditionsViolated.size(), componentUuid));
            final Map<Policy, List<PolicyCondition>> violatedConditionsByPolicy = conditionsViolated.stream()
                    .collect(Collectors.groupingBy(PolicyCondition::getPolicy));

            // Create policy violations, but only do so when the detected condition violations
            // match the configured policy operator. When the operator is ALL, and not all conditions
            // of the policy were violated, we don't want to create any violations.
            final List<PolicyViolation> violations = violatedConditionsByPolicy.entrySet().stream()
                    .flatMap(policyAndViolatedConditions -> {
                        final Policy policy = policyAndViolatedConditions.getKey();
                        final List<PolicyCondition> violatedConditions = policyAndViolatedConditions.getValue();

                        if ((policy.getOperator() == Policy.Operator.ANY && !violatedConditions.isEmpty())
                                || (policy.getOperator() == Policy.Operator.ALL && violatedConditions.size() == policy.getPolicyConditions().size())) {
                            // TODO: Only a single violation should be raised, and instead multiple matched conditions
                            //   should be associated with it. Keeping the existing behavior in order to avoid having to
                            //   touch too much persistence and REST API code.
                            return violatedConditions.stream()
                                    .map(condition -> {
                                        final var violation = new PolicyViolation();
                                        violation.setComponent(component);
                                        violation.setType(condition.getViolationType());
                                        violation.setPolicyCondition(condition);
                                        violation.setTimestamp(new Date());
                                        return violation;
                                    });
                        }

                        return Stream.empty();
                    })
                    .filter(Objects::nonNull)
                    .toList();

            // Reconcile the violations created above with what's already in the database.
            // Create new records if necessary, and delete records that are no longer current.
            final List<PolicyViolation> newViolations = reconcileViolations(qm, component, violations);

            // Notify users about any new violations.
            for (final PolicyViolation newViolation : newViolations) {
                NotificationUtil.analyzeNotificationCriteria(qm, newViolation);
            }
        } finally {
            timerSample.stop(Timer
                    .builder("dtrack_policy_eval")
                    .tag("target", "component")
                    .register(Metrics.getRegistry()));
        }

        LOGGER.info("Policy evaluation completed for component %s".formatted(componentUuid));
    }

    // TODO: Move to PolicyQueryManager
    private static List<Policy> getApplicablePolicies(final QueryManager qm, final Project project) {
        var filter = """
                (this.projects.isEmpty() && this.tags.isEmpty())
                    || (this.projects.contains(:project)
                """;
        var params = new HashMap<String, Object>();
        params.put("project", project);

        // To compensate for missing support for recursion of Common Table Expressions (CTEs)
        // in JDO, we have to fetch the UUIDs of all parent projects upfront. Otherwise, we'll
        // not be able to evaluate whether the policy is inherited from parent projects.
        var variables = "";
        final List<UUID> parentUuids = getParents(qm, project);
        if (!parentUuids.isEmpty()) {
            filter += """
                    || (this.includeChildren
                        && this.projects.contains(parentVar)
                        && :parentUuids.contains(parentVar.uuid))
                    """;
            variables += "org.dependencytrack.model.Project parentVar";
            params.put("parentUuids", parentUuids);
        }
        filter += ")";

        // DataNucleus generates an invalid SQL query when using the idiomatic solution.
        // The following works, but it's ugly and likely doesn't perform well if the project
        // has many tags. Worth trying the idiomatic way again once DN has been updated to > 6.0.4.
        //
        // filter += " || (this.tags.contains(commonTag) && :project.tags.contains(commonTag))";
        // variables += "org.dependencytrack.model.Tag commonTag";
        if (project.getTags() != null && !project.getTags().isEmpty()) {
            filter += " || (";
            for (int i = 0; i < project.getTags().size(); i++) {
                filter += "this.tags.contains(:tag" + i + ")";
                params.put("tag" + i, project.getTags().get(i));
                if (i < (project.getTags().size() - 1)) {
                    filter += " || ";
                }
            }
            filter += ")";
        }

        final List<Policy> policies;
        final Query<Policy> query = qm.getPersistenceManager().newQuery(Policy.class);
        try {
            query.setFilter(filter);
            query.setNamedParameters(params);
            if (!variables.isEmpty()) {
                query.declareVariables(variables);
            }
            policies = List.copyOf(query.executeList());
        } finally {
            query.closeAll();
        }

        return policies;
    }

    // TODO: Move to ProjectQueryManager
    private static List<UUID> getParents(final QueryManager qm, final Project project) {
        return getParents(qm, project.getUuid(), new ArrayList<>());
    }

    // TODO: Move to ProjectQueryManager
    private static List<UUID> getParents(final QueryManager qm, final UUID uuid, final List<UUID> parents) {
        final UUID parentUuid;
        final Query<Project> query = qm.getPersistenceManager().newQuery(Project.class);
        try {
            query.setFilter("uuid == :uuid && parent != null");
            query.setParameters(uuid);
            query.setResult("parent.uuid");
            parentUuid = query.executeResultUnique(UUID.class);
        } finally {
            query.closeAll();
        }

        if (parentUuid == null) {
            return parents;
        }

        parents.add(parentUuid);
        return getParents(qm, parentUuid, parents);
    }

    private static ProjectProjection fetchProject(final QueryManager qm, final long projectId, final Collection<String> protoFieldNames) {
        final String sqlSelectColumns = getFieldMappings(ProjectProjection.class).stream()
                .filter(mapping -> protoFieldNames.contains(mapping.protoFieldName()))
                .map(mapping -> "\"%s\" AS \"%s\"".formatted(mapping.sqlColumnName(), mapping.javaFieldName()))
                .collect(Collectors.joining(", "));

        final Query<?> query = qm.getPersistenceManager().newQuery(Query.SQL, """
                SELECT %s FROM "PROJECT" WHERE "ID" = ?
                """.formatted(sqlSelectColumns));
        query.setParameters(projectId);
        try {
            return query.executeResultUnique(ProjectProjection.class);
        } finally {
            query.closeAll();
        }
    }

    private static org.hyades.proto.policy.v1.Project mapProject(final ProjectProjection projection) {
        return org.hyades.proto.policy.v1.Project.newBuilder()
                .setUuid(trimToEmpty(projection.uuid))
                .setGroup(trimToEmpty(projection.group))
                .setName(trimToEmpty(projection.name))
                .setVersion(trimToEmpty(projection.version))
                // .addAllTags(project.getTags().stream().map(Tag::getName).toList())
                .setCpe(trimToEmpty(projection.cpe))
                .setPurl(trimToEmpty(projection.purl))
                .setSwidTagId(trimToEmpty(projection.swidTagId))
                .build();
    }

    private static List<ComponentProjection> fetchComponents(final QueryManager qm, final long projectId, final Collection<String> protoFieldNames) {
        final String sqlSelectColumns = Stream.concat(
                        Stream.of(ComponentProjection.ID_FIELD_MAPPING),
                        getFieldMappings(ComponentProjection.class).stream()
                                .filter(mapping -> protoFieldNames.contains(mapping.protoFieldName()))
                )
                .map(mapping -> "\"%s\" AS \"%s\"".formatted(mapping.sqlColumnName(), mapping.javaFieldName()))
                .collect(Collectors.joining(", "));

        final Query<?> query = qm.getPersistenceManager().newQuery(Query.SQL, """
                SELECT %s FROM "COMPONENT" WHERE "PROJECT_ID" = ?
                """.formatted(sqlSelectColumns));
        query.setParameters(projectId);
        try {
            return List.copyOf(query.executeResultList(ComponentProjection.class));
        } finally {
            query.closeAll();
        }
    }

    private static org.hyades.proto.policy.v1.Component mapComponent(final ComponentProjection projection,
                                                                     final Map<Long, License> licensesById) {
        final org.hyades.proto.policy.v1.Component.Builder componentBuilder =
                org.hyades.proto.policy.v1.Component.newBuilder()
                        .setUuid(trimToEmpty(projection.uuid))
                        .setGroup(trimToEmpty(projection.group))
                        .setName(trimToEmpty(projection.name))
                        .setVersion(trimToEmpty(projection.name))
                        .setClassifier(trimToEmpty(projection.classifier))
                        .setCpe(trimToEmpty(projection.cpe))
                        .setPurl(trimToEmpty(projection.purl))
                        .setSwidTagId(trimToEmpty(projection.swidTagId))
                        .setIsInternal(Optional.ofNullable(projection.internal).orElse(false))
                        .setMd5(trimToEmpty(projection.md5))
                        .setSha1(trimToEmpty(projection.sha1))
                        .setSha256(trimToEmpty(projection.sha256))
                        .setSha384(trimToEmpty(projection.sha384))
                        .setSha512(trimToEmpty(projection.sha512))
                        .setSha3256(trimToEmpty(projection.sha3_256))
                        .setSha3384(trimToEmpty(projection.sha3_384))
                        .setSha3512(trimToEmpty(projection.sha3_512))
                        .setBlake2B256(trimToEmpty(projection.blake2b_256))
                        .setBlake2B384(trimToEmpty(projection.blake2b_384))
                        .setBlake2B512(trimToEmpty(projection.blake2b_512))
                        .setBlake3(trimToEmpty(projection.blake3));

        if (projection.resolvedLicenseId != null && projection.resolvedLicenseId > 0) {
            componentBuilder.setResolvedLicense(licensesById.get(projection.resolvedLicenseId));
        }

        return componentBuilder.build();
    }

    private static List<ComponentsVulnerabilitiesProjection> fetchComponentsVulnerabilities(final QueryManager qm, final long projectId) {
        final Query<?> query = qm.getPersistenceManager().newQuery(Query.SQL, """
                SELECT
                  "CV"."COMPONENT_ID" AS "componentId",
                  "CV"."VULNERABILITY_ID" AS "vulnerabilityId"
                FROM
                  "COMPONENTS_VULNERABILITIES" AS "CV"
                INNER JOIN
                  "COMPONENT" AS "C" ON "C"."ID" = "CV"."COMPONENT_ID"
                WHERE
                  "C"."PROJECT_ID" = ?
                """);
        query.setParameters(projectId);
        try {
            return List.copyOf(query.executeResultList(ComponentsVulnerabilitiesProjection.class));
        } finally {
            query.closeAll();
        }
    }

    private static List<LicenseProjection> fetchLicenses(final QueryManager qm, final long projectId,
                                                         final Collection<String> licenseProtoFieldNames,
                                                         final Collection<String> licenseGroupProtoFieldNames) {
        final String licenseSqlSelectColumns = Stream.concat(
                        Stream.of(LicenseProjection.ID_FIELD_MAPPING),
                        getFieldMappings(LicenseProjection.class).stream()
                                .filter(mapping -> licenseProtoFieldNames.contains(mapping.protoFieldName()))
                )
                .map(mapping -> "\"L\".\"%s\" AS \"%s\"".formatted(mapping.sqlColumnName(), mapping.javaFieldName()))
                .collect(Collectors.joining(", "));

        if (!licenseProtoFieldNames.contains("groups")) {
            final Query<?> query = qm.getPersistenceManager().newQuery(Query.SQL, """
                    SELECT DISTINCT
                      %s
                    FROM
                      "LICENSE" AS "L"
                    INNER JOIN
                      "COMPONENT" AS "C" ON "C"."LICENSE_ID" = "L"."ID"
                    WHERE
                      "C"."PROJECT_ID" = ?
                    """.formatted(licenseSqlSelectColumns));
            query.setParameters(projectId);
            try {
                return List.copyOf(query.executeResultList(LicenseProjection.class));
            } finally {
                query.closeAll();
            }
        }

        final String licenseSqlGroupByColumns = Stream.concat(
                        Stream.of(LicenseProjection.ID_FIELD_MAPPING),
                        getFieldMappings(LicenseProjection.class).stream()
                                .filter(mapping -> licenseProtoFieldNames.contains(mapping.protoFieldName()))
                )
                .map(mapping -> "\"L\".\"%s\"".formatted(mapping.sqlColumnName()))
                .collect(Collectors.joining(", "));

        final String licenseGroupSqlSelectColumns = getFieldMappings(LicenseGroupProjection.class).stream()
                .filter(mapping -> licenseGroupProtoFieldNames.contains(mapping.protoFieldName()))
                .map(mapping -> "'%s', \"LG\".\"%s\"".formatted(mapping.javaFieldName(), mapping.sqlColumnName()))
                .collect(Collectors.joining(", "));

        final Query<?> query = qm.getPersistenceManager().newQuery(Query.SQL, """
                SELECT DISTINCT
                  "L"."ID" AS "id",
                  %s,
                  CAST(JSONB_AGG(DISTINCT JSONB_BUILD_OBJECT(%s)) AS TEXT) AS "licenseGroupsJson"
                FROM
                  "LICENSE" AS "L"
                INNER JOIN
                  "COMPONENT" AS "C" ON "C"."LICENSE_ID" = "L"."ID"
                LEFT JOIN
                  "LICENSEGROUP_LICENSE" AS "LGL" ON "LGL"."LICENSE_ID" = "L"."ID"
                LEFT JOIN
                  "LICENSEGROUP" AS "LG" ON "LG"."ID" = "LGL"."LICENSEGROUP_ID"
                WHERE
                  "C"."PROJECT_ID" = ?
                GROUP BY
                  %s
                """.formatted(licenseSqlSelectColumns, licenseGroupSqlSelectColumns, licenseSqlGroupByColumns));
        query.setParameters(projectId);
        try {
            return List.copyOf(query.executeResultList(LicenseProjection.class));
        } finally {
            query.closeAll();
        }
    }

    private static License mapLicense(final LicenseProjection licenseProjection) {
        final License.Builder licenseBuilder = License.newBuilder()
                .setUuid(trimToEmpty(licenseProjection.uuid))
                .setId(trimToEmpty(licenseProjection.licenseId))
                .setName(trimToEmpty(licenseProjection.name));
        Optional.ofNullable(licenseProjection.isOsiApproved).ifPresent(licenseBuilder::setIsOsiApproved);
        Optional.ofNullable(licenseProjection.isFsfLibre).ifPresent(licenseBuilder::setIsFsfLibre);
        Optional.ofNullable(licenseProjection.isDeprecatedId).ifPresent(licenseBuilder::setIsDeprecatedId);
        Optional.ofNullable(licenseProjection.isCustomLicense).ifPresent(licenseBuilder::setIsCustom);

        if (licenseProjection.licenseGroupsJson != null) {
            try {
                final ArrayNode groupsArray = OBJECT_MAPPER.readValue(licenseProjection.licenseGroupsJson, ArrayNode.class);
                for (final JsonNode groupNode : groupsArray) {
                    licenseBuilder.addGroups(License.Group.newBuilder()
                            .setUuid(Optional.ofNullable(groupNode.get("uuid")).map(JsonNode::asText).orElse(""))
                            .setName(Optional.ofNullable(groupNode.get("name")).map(JsonNode::asText).orElse(""))
                            .build());
                }
            } catch (JacksonException e) {
                LOGGER.warn("Failed to parse license groups JSON", e);
            }
        }

        return licenseBuilder.build();
    }

    private static List<VulnerabilityProjection> fetchVulnerabilities(final QueryManager qm, final long projectId, final Collection<String> protoFieldNames) {
        final String sqlSelectColumns = getFieldMappings(VulnerabilityProjection.class).stream()
                .filter(mapping -> protoFieldNames.contains(mapping.protoFieldName()))
                .map(mapping -> "\"V\".\"%s\" AS \"%s\"".formatted(mapping.sqlColumnName(), mapping.javaFieldName()))
                .collect(Collectors.joining(", "));

        // TODO: Aliases could be fetched in the same query, using a JSONB aggregate.
        // SELECT DISTINCT
        //   "V"."ID" AS "id",
        //   "V"."VULNID" AS "vulnId",
        //   "V"."SOURCE" AS "source",
        //   (SELECT
        //      JSONB_AGG(DISTINCT JSONB_STRIP_NULLS(JSONB_BUILD_OBJECT(
        //        'cveId', "VA"."CVE_ID",
        //        'ghsaId', "VA"."GHSA_ID",
        //        'gsdId', "VA"."GSD_ID",
        //        'internalId', "VA"."INTERNAL_ID",
        //        'osvId', "VA"."OSV_ID",
        //        'sonatypeId', "VA"."SONATYPE_ID",
        //        'snykId', "VA"."SNYK_ID",
        //        'vulnDbId', "VA"."VULNDB_ID"
        //      )))::TEXT
        //    FROM
        //      "VULNERABILITYALIAS" AS "VA"
        //    WHERE
        //      ("V"."SOURCE" = 'NVD' AND "VA"."CVE_ID" = "V"."VULNID")
        //      OR ("V"."SOURCE" = 'SNYK' AND "VA"."SNYK_ID" = "V"."VULNID")
        //      -- OR ...
        //   ) AS "aliasesJson"
        // FROM
        //   "VULNERABILITY" AS "V"
        // INNER JOIN
        //   "COMPONENTS_VULNERABILITIES" AS "CV" ON "CV"."VULNERABILITY_ID" = "V"."ID"
        // INNER JOIN
        //   "COMPONENT" AS "C" ON "C"."ID" = "CV"."COMPONENT_ID"
        // WHERE
        //   "C"."PROJECT_ID" = ?;

        final Query<?> query = qm.getPersistenceManager().newQuery(Query.SQL, """
                SELECT DISTINCT
                  "V"."ID" AS "id",
                  %s
                FROM
                  "VULNERABILITY" AS "V"
                INNER JOIN
                  "COMPONENTS_VULNERABILITIES" AS "CV" ON "CV"."VULNERABILITY_ID" = "V"."ID"
                INNER JOIN
                  "COMPONENT" AS "C" ON "C"."ID" = "CV"."COMPONENT_ID"
                WHERE
                  "C"."PROJECT_ID" = ?
                """.formatted(sqlSelectColumns));
        query.setParameters(projectId);
        try {
            return List.copyOf(query.executeResultList(VulnerabilityProjection.class));
        } finally {
            query.closeAll();
        }
    }

    private static org.hyades.proto.policy.v1.Component mapComponent(final QueryManager qm,
                                                                     final Component component,
                                                                     final MultiValuedMap<Type, String> requirements) {
        // TODO: Load only required fields
        final org.hyades.proto.policy.v1.Component.Builder builder =
                org.hyades.proto.policy.v1.Component.newBuilder()
                        .setUuid(Optional.ofNullable(component.getUuid()).map(UUID::toString).orElse(""))
                        .setGroup(trimToEmpty(component.getGroup()))
                        .setName(trimToEmpty(component.getName()))
                        .setVersion(trimToEmpty(component.getVersion()))
                        .setClassifier(Optional.ofNullable(component.getClassifier()).map(Enum::name).orElse(""))
                        .setCpe(trimToEmpty(component.getCpe()))
                        .setPurl(Optional.ofNullable(component.getPurl()).map(PackageURL::canonicalize).orElse(""))
                        .setSwidTagId(trimToEmpty(component.getSwidTagId()))
                        .setIsInternal(component.isInternal())
                        .setMd5(trimToEmpty(component.getMd5()))
                        .setSha1(trimToEmpty(component.getSha1()))
                        .setSha256(trimToEmpty(component.getSha256()))
                        .setSha384(trimToEmpty(component.getSha384()))
                        .setSha512(trimToEmpty(component.getSha512()))
                        .setSha3256(trimToEmpty(component.getSha3_256()))
                        .setSha3384(trimToEmpty(component.getSha3_384()))
                        .setSha3512(trimToEmpty(component.getSha3_512()))
                        .setBlake2B256(trimToEmpty(component.getBlake2b_256()))
                        .setBlake2B384(trimToEmpty(component.getBlake2b_384()))
                        .setBlake2B512(trimToEmpty(component.getBlake2b_512()))
                        .setBlake3(trimToEmpty(component.getBlake3()));

        if (requirements.get(TYPE_COMPONENT).contains("is_direct_dependency")
                && component.getProject().getDirectDependencies() != null) {
            try {
                final ArrayNode dependencyArray = OBJECT_MAPPER.readValue(component.getProject().getDirectDependencies(), ArrayNode.class);
                for (final JsonNode dependencyNode : dependencyArray) {
                    if (dependencyNode.get("uuid") != null && dependencyNode.get("uuid").asText().equals(component.getUuid().toString())) {
                        builder.setIsDirectDependency(true);
                        break;
                    }
                }
            } catch (JacksonException | RuntimeException e) {
                LOGGER.warn("Failed to parse direct dependencies of project %s".formatted(component.getProject().getUuid()), e);
            }
        }

        if (requirements.containsKey(TYPE_LICENSE) && component.getResolvedLicense() != null) {
            final License.Builder licenseBuilder = License.newBuilder()
                    .setUuid(Optional.ofNullable(component.getResolvedLicense().getUuid()).map(UUID::toString).orElse(""))
                    .setId(trimToEmpty(component.getResolvedLicense().getLicenseId()))
                    .setName(trimToEmpty(component.getResolvedLicense().getName()))
                    .setIsOsiApproved(component.getResolvedLicense().isOsiApproved())
                    .setIsFsfLibre(component.getResolvedLicense().isFsfLibre())
                    .setIsDeprecatedId(component.getResolvedLicense().isDeprecatedLicenseId())
                    .setIsCustom(component.getResolvedLicense().isCustomLicense());

            if (requirements.containsKey(TYPE_LICENSE_GROUP)
                    || requirements.get(TYPE_LICENSE).contains("groups")) {
                final Query<LicenseGroup> licenseGroupQuery = qm.getPersistenceManager().newQuery(LicenseGroup.class);
                licenseGroupQuery.setFilter("licenses.contains(:license)");
                licenseGroupQuery.setNamedParameters(Map.of("license", component.getResolvedLicense()));
                licenseGroupQuery.setResult("uuid, name");
                try {
                    licenseGroupQuery.executeResultList(LicenseGroup.class).stream()
                            .map(licenseGroup -> License.Group.newBuilder()
                                    .setUuid(Optional.ofNullable(licenseGroup.getUuid()).map(UUID::toString).orElse(""))
                                    .setName(trimToEmpty(licenseGroup.getName())))
                            .forEach(licenseBuilder::addGroups);
                } finally {
                    licenseGroupQuery.closeAll();
                }
            }

            builder.setResolvedLicense(licenseBuilder);
        }

        return builder.build();
    }

    private static org.hyades.proto.policy.v1.Project mapProject(final Project project,
                                                                 final MultiValuedMap<Type, String> requirements) {
        if (!requirements.containsKey(TYPE_PROJECT)) {
            return org.hyades.proto.policy.v1.Project.getDefaultInstance();
        }

        // TODO: Load only required fields
        final org.hyades.proto.policy.v1.Project.Builder builder =
                org.hyades.proto.policy.v1.Project.newBuilder()
                        .setUuid(Optional.ofNullable(project.getUuid()).map(UUID::toString).orElse(""))
                        .setGroup(trimToEmpty(project.getGroup()))
                        .setName(trimToEmpty(project.getName()))
                        .setVersion(trimToEmpty(project.getVersion()))
                        .addAllTags(project.getTags().stream().map(Tag::getName).toList())
                        .setCpe(trimToEmpty(project.getCpe()))
                        .setPurl(Optional.ofNullable(project.getPurl()).map(PackageURL::canonicalize).orElse(""))
                        .setSwidTagId(trimToEmpty(project.getSwidTagId()));

        if (requirements.containsKey(TYPE_PROJECT_PROPERTY)
                || requirements.get(TYPE_PROJECT).contains("properties")) {
            // TODO
        }

        return builder.build();
    }

    private static List<Vulnerability> loadVulnerabilities(final QueryManager qm,
                                                           final Component component,
                                                           final MultiValuedMap<Type, String> requirements) {
        if (!requirements.containsKey(TYPE_VULNERABILITY)) {
            return emptyList();
        }

        // TODO: Load only required fields
        final Query<org.dependencytrack.model.Vulnerability> query =
                qm.getPersistenceManager().newQuery(org.dependencytrack.model.Vulnerability.class);
        query.getFetchPlan().clearGroups();
        query.getFetchPlan().setGroup(org.dependencytrack.model.Vulnerability.FetchGroup.POLICY.name());
        query.setFilter("components.contains(:component)");
        query.setParameters(component);
        final List<org.dependencytrack.model.Vulnerability> vulns;
        try {
            vulns = (List<org.dependencytrack.model.Vulnerability>) qm.getPersistenceManager().detachCopyAll(query.executeList());
        } finally {
            query.closeAll();
        }

        final List<Vulnerability.Builder> vulnBuilders = vulns.stream()
                .map(v -> {
                    final Vulnerability.Builder builder = Vulnerability.newBuilder()
                            .setUuid(v.getUuid().toString())
                            .setId(trimToEmpty(v.getVulnId()))
                            .setSource(trimToEmpty(v.getSource()))
                            .setCvssv2Vector(trimToEmpty(v.getCvssV2Vector()))
                            .setCvssv3Vector(trimToEmpty(v.getCvssV3Vector()))
                            .setOwaspRrVector(trimToEmpty(v.getOwaspRRVector()))
                            .setSeverity(v.getSeverity().name());
                    Optional.ofNullable(v.getCwes()).ifPresent(builder::addAllCwes);
                    Optional.ofNullable(v.getCvssV2BaseScore()).map(BigDecimal::doubleValue).ifPresent(builder::setCvssv2BaseScore);
                    Optional.ofNullable(v.getCvssV2ImpactSubScore()).map(BigDecimal::doubleValue).ifPresent(builder::setCvssv2ImpactSubscore);
                    Optional.ofNullable(v.getCvssV2ExploitabilitySubScore()).map(BigDecimal::doubleValue).ifPresent(builder::setCvssv2ExploitabilitySubscore);
                    Optional.ofNullable(v.getCvssV3BaseScore()).map(BigDecimal::doubleValue).ifPresent(builder::setCvssv3BaseScore);
                    Optional.ofNullable(v.getCvssV3ImpactSubScore()).map(BigDecimal::doubleValue).ifPresent(builder::setCvssv3ImpactSubscore);
                    Optional.ofNullable(v.getCvssV3ExploitabilitySubScore()).map(BigDecimal::doubleValue).ifPresent(builder::setCvssv3ExploitabilitySubscore);
                    Optional.ofNullable(v.getOwaspRRLikelihoodScore()).map(BigDecimal::doubleValue).ifPresent(builder::setOwaspRrLikelihoodScore);
                    Optional.ofNullable(v.getOwaspRRTechnicalImpactScore()).map(BigDecimal::doubleValue).ifPresent(builder::setOwaspRrTechnicalImpactScore);
                    Optional.ofNullable(v.getOwaspRRBusinessImpactScore()).map(BigDecimal::doubleValue).ifPresent(builder::setOwaspRrBusinessImpactScore);
                    Optional.ofNullable(v.getEpssScore()).map(BigDecimal::doubleValue).ifPresent(builder::setEpssScore);
                    Optional.ofNullable(v.getEpssPercentile()).map(BigDecimal::doubleValue).ifPresent(builder::setEpssPercentile);
                    Optional.ofNullable(v.getCreated()).map(Timestamps::fromDate).ifPresent(builder::setCreated);
                    Optional.ofNullable(v.getPublished()).map(Timestamps::fromDate).ifPresent(builder::setPublished);
                    Optional.ofNullable(v.getUpdated()).map(Timestamps::fromDate).ifPresent(builder::setUpdated);

                    if (requirements.containsKey(TYPE_VULNERABILITY_ALIAS)
                            || requirements.get(TYPE_VULNERABILITY).contains("aliases")) {
                        // TODO: Dirty hack, create a proper solution. Likely needs caching, too.
                        final var tmpVuln = new org.dependencytrack.model.Vulnerability();
                        tmpVuln.setVulnId(builder.getId());
                        tmpVuln.setSource(builder.getSource());
                        tmpVuln.setAliases(qm.getVulnerabilityAliases(tmpVuln));
                        VulnerabilityUtil.getUniqueAliases(tmpVuln).stream()
                                .map(alias -> Vulnerability.Alias.newBuilder()
                                        .setId(alias.getKey().name())
                                        .setSource(alias.getValue())
                                        .build())
                                .forEach(builder::addAliases);
                    }

                    return builder;
                })
                .toList();

        return vulnBuilders.stream()
                .map(Vulnerability.Builder::build)
                .toList();
    }

    // TODO: Move to PolicyQueryManager
    private static List<PolicyViolation> reconcileViolations(final QueryManager qm, final Component component, final List<PolicyViolation> violations) {
        final var newViolations = new ArrayList<PolicyViolation>();

        final Transaction trx = qm.getPersistenceManager().currentTransaction();
        try {
            trx.begin();

            final var violationIdsToKeep = new HashSet<Long>();

            for (final PolicyViolation violation : violations) {
                final Query<PolicyViolation> query = qm.getPersistenceManager().newQuery(PolicyViolation.class);
                query.setFilter("component == :component && policyCondition == :policyCondition && type == :type");
                query.setNamedParameters(Map.of(
                        "component", violation.getComponent(),
                        "policyCondition", violation.getPolicyCondition(),
                        "type", violation.getType()
                ));
                query.setResult("id");

                final Long existingViolationId;
                try {
                    existingViolationId = query.executeResultUnique(Long.class);
                } finally {
                    query.closeAll();
                }

                if (existingViolationId != null) {
                    violationIdsToKeep.add(existingViolationId);
                } else {
                    qm.getPersistenceManager().makePersistent(violation);
                    violationIdsToKeep.add(violation.getId());
                    newViolations.add(violation);
                }
            }

            final Query<PolicyViolation> deleteQuery = qm.getPersistenceManager().newQuery(PolicyViolation.class);
            deleteQuery.setFilter("component == :component && !:ids.contains(id)");
            try {
                final long violationsDeleted = deleteQuery.deletePersistentAll(component, violationIdsToKeep);
                LOGGER.debug("Deleted %s outdated violations".formatted(violationsDeleted)); // TODO: Add component UUID
            } finally {
                deleteQuery.closeAll();
            }

            trx.commit();
        } finally {
            if (trx.isActive()) {
                trx.rollback();
            }
        }

        return newViolations;
    }

}
