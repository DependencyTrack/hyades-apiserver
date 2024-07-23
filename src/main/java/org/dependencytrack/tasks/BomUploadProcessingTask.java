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
package org.dependencytrack.tasks;

import alpine.Config;
import alpine.common.logging.Logger;
import alpine.event.framework.ChainableEvent;
import alpine.event.framework.Event;
import alpine.event.framework.EventService;
import alpine.event.framework.Subscriber;
import alpine.notification.Notification;
import alpine.notification.NotificationLevel;
import org.apache.commons.collections4.MultiValuedMap;
import org.apache.commons.collections4.multimap.HashSetValuedHashMap;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.cyclonedx.exception.ParseException;
import org.cyclonedx.parsers.BomParserFactory;
import org.cyclonedx.parsers.Parser;
import org.datanucleus.flush.FlushMode;
import org.datanucleus.store.query.QueryNotUniqueException;
import org.dependencytrack.common.ConfigKey;
import org.dependencytrack.event.BomUploadEvent;
import org.dependencytrack.event.ComponentRepositoryMetaAnalysisEvent;
import org.dependencytrack.event.ComponentVulnerabilityAnalysisEvent;
import org.dependencytrack.event.IntegrityAnalysisEvent;
import org.dependencytrack.event.ProjectMetricsUpdateEvent;
import org.dependencytrack.event.kafka.KafkaEventDispatcher;
import org.dependencytrack.event.kafka.componentmeta.AbstractMetaHandler;
import org.dependencytrack.model.Bom;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ComponentIdentity;
import org.dependencytrack.model.FetchStatus;
import org.dependencytrack.model.IntegrityMetaComponent;
import org.dependencytrack.model.License;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectMetadata;
import org.dependencytrack.model.ServiceComponent;
import org.dependencytrack.model.VulnerabilityAnalysisLevel;
import org.dependencytrack.model.VulnerabilityScan.TargetType;
import org.dependencytrack.model.WorkflowState;
import org.dependencytrack.model.WorkflowStatus;
import org.dependencytrack.model.WorkflowStep;
import org.dependencytrack.notification.NotificationConstants;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.notification.vo.BomConsumedOrProcessed;
import org.dependencytrack.notification.vo.BomProcessingFailed;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.util.InternalComponentIdentifier;
import org.dependencytrack.util.WaitingLockConfiguration;
import org.json.JSONArray;
import org.slf4j.MDC;

import javax.jdo.JDOUserException;
import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.Predicate;

import static org.apache.commons.lang3.StringUtils.isNotBlank;
import static org.apache.commons.lang3.StringUtils.trim;
import static org.apache.commons.lang3.StringUtils.trimToNull;
import static org.apache.commons.lang3.time.DurationFormatUtils.formatDurationHMS;
import static org.datanucleus.PropertyNames.PROPERTY_FLUSH_MODE;
import static org.datanucleus.PropertyNames.PROPERTY_PERSISTENCE_BY_REACHABILITY_AT_COMMIT;
import static org.datanucleus.PropertyNames.PROPERTY_RETAIN_VALUES;
import static org.dependencytrack.common.MdcKeys.MDC_BOM_FORMAT;
import static org.dependencytrack.common.MdcKeys.MDC_BOM_SERIAL_NUMBER;
import static org.dependencytrack.common.MdcKeys.MDC_BOM_SPEC_VERSION;
import static org.dependencytrack.common.MdcKeys.MDC_BOM_UPLOAD_TOKEN;
import static org.dependencytrack.common.MdcKeys.MDC_BOM_VERSION;
import static org.dependencytrack.common.MdcKeys.MDC_PROJECT_NAME;
import static org.dependencytrack.common.MdcKeys.MDC_PROJECT_UUID;
import static org.dependencytrack.common.MdcKeys.MDC_PROJECT_VERSION;
import static org.dependencytrack.event.kafka.componentmeta.RepoMetaConstants.SUPPORTED_PACKAGE_URLS_FOR_INTEGRITY_CHECK;
import static org.dependencytrack.event.kafka.componentmeta.RepoMetaConstants.TIME_SPAN;
import static org.dependencytrack.parser.cyclonedx.util.ModelConverter.convertComponents;
import static org.dependencytrack.parser.cyclonedx.util.ModelConverter.convertDependencyGraph;
import static org.dependencytrack.parser.cyclonedx.util.ModelConverter.convertServices;
import static org.dependencytrack.parser.cyclonedx.util.ModelConverter.convertToProject;
import static org.dependencytrack.parser.cyclonedx.util.ModelConverter.convertToProjectMetadata;
import static org.dependencytrack.parser.cyclonedx.util.ModelConverter.flatten;
import static org.dependencytrack.proto.repometaanalysis.v1.FetchMeta.FETCH_META_INTEGRITY_DATA_AND_LATEST_VERSION;
import static org.dependencytrack.proto.repometaanalysis.v1.FetchMeta.FETCH_META_LATEST_VERSION;
import static org.dependencytrack.util.LockProvider.executeWithLockWaiting;
import static org.dependencytrack.util.PersistenceUtil.applyIfChanged;
import static org.dependencytrack.util.PersistenceUtil.assertPersistent;

/**
 * Subscriber task that performs processing of bill-of-material (bom)
 * when it is uploaded.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public class BomUploadProcessingTask implements Subscriber {

    private static final class Context {

        private final UUID token;
        private final Project project;
        private final Bom.Format bomFormat;
        private final long startTimeNs;
        private String bomSpecVersion;
        private String bomSerialNumber;
        private Date bomTimestamp;
        private Integer bomVersion;

        private Context(final UUID token, final Project project) {
            this.token = token;
            this.project = project;
            this.bomFormat = Bom.Format.CYCLONEDX;
            this.startTimeNs = System.nanoTime();
        }

    }

    private static final Logger LOGGER = Logger.getLogger(BomUploadProcessingTask.class);

    private final KafkaEventDispatcher kafkaEventDispatcher;
    private final boolean delayBomProcessedNotification;

    public BomUploadProcessingTask() {
        this(new KafkaEventDispatcher(), Config.getInstance().getPropertyAsBoolean(ConfigKey.TMP_DELAY_BOM_PROCESSED_NOTIFICATION));
    }

    BomUploadProcessingTask(final KafkaEventDispatcher kafkaEventDispatcher, final boolean delayBomProcessedNotification) {
        this.kafkaEventDispatcher = kafkaEventDispatcher;
        this.delayBomProcessedNotification = delayBomProcessedNotification;
    }

    /**
     * {@inheritDoc}
     */
    public void inform(final Event e) {
        if (!(e instanceof final BomUploadEvent event)) {
            return;
        }

        final var ctx = new Context(event.getChainIdentifier(), event.getProject());
        try (var ignoredMdcProjectUuid = MDC.putCloseable(MDC_PROJECT_UUID, ctx.project.getUuid().toString());
             var ignoredMdcProjectName = MDC.putCloseable(MDC_PROJECT_NAME, ctx.project.getName());
             var ignoredMdcProjectVersion = MDC.putCloseable(MDC_PROJECT_VERSION, ctx.project.getVersion());
             var ignoredMdcBomUploadToken = MDC.putCloseable(MDC_BOM_UPLOAD_TOKEN, ctx.token.toString())) {
            processEvent(ctx, event);
        }
    }

    private void processEvent(final Context ctx, final BomUploadEvent event) {
        startBomConsumptionWorkflowStep(ctx);

        final ConsumedBom consumedBom;
        try (final var bomFileInputStream = Files.newInputStream(event.getFile().toPath(), StandardOpenOption.DELETE_ON_CLOSE)) {
            final byte[] cdxBomBytes = bomFileInputStream.readAllBytes();
            final Parser parser = BomParserFactory.createParser(cdxBomBytes);
            final org.cyclonedx.model.Bom cdxBom = parser.parse(cdxBomBytes);

            ctx.bomSpecVersion = cdxBom.getSpecVersion();
            if (cdxBom.getSerialNumber() != null) {
                ctx.bomSerialNumber = cdxBom.getSerialNumber().replaceFirst("urn:uuid:", "");
            }
            if (cdxBom.getMetadata() != null && cdxBom.getMetadata().getTimestamp() != null) {
                ctx.bomTimestamp = cdxBom.getMetadata().getTimestamp();
            }
            ctx.bomVersion = cdxBom.getVersion();

            consumedBom = consumeBom(cdxBom);
        } catch (IOException | ParseException | RuntimeException e) {
            failWorkflowStepAndCancelDescendants(ctx, WorkflowStep.BOM_CONSUMPTION, e);
            dispatchBomProcessingFailedNotification(ctx, e);
            return;
        }

        startBomProcessingWorkflowStep(ctx);
        dispatchBomConsumedNotification(ctx);

        final ProcessedBom processedBom;
        try (var ignoredMdcBomFormat = MDC.putCloseable(MDC_BOM_FORMAT, ctx.bomFormat.getFormatShortName());
             var ignoredMdcBomSpecVersion = MDC.putCloseable(MDC_BOM_SPEC_VERSION, ctx.bomSpecVersion);
             var ignoredMdcBomSerialNumber = MDC.putCloseable(MDC_BOM_SERIAL_NUMBER, ctx.bomSerialNumber);
             var ignoredMdcBomVersion = MDC.putCloseable(MDC_BOM_VERSION, String.valueOf(ctx.bomVersion))) {
            // Prevent BOMs for the same project to be processed concurrently.
            // Note that this is an edge case, we're not expecting any lock waits under normal circumstances.
            final WaitingLockConfiguration lockConfiguration = createLockConfiguration(ctx);
            processedBom = executeWithLockWaiting(lockConfiguration, () -> processBom(ctx, consumedBom));
        } catch (Throwable e) {
            failWorkflowStepAndCancelDescendants(ctx, WorkflowStep.BOM_PROCESSING, e);
            dispatchBomProcessingFailedNotification(ctx, e);
            return;
        }

        completeBomProcessingWorkflowStep(ctx);
        final var processingDurationMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - ctx.startTimeNs);
        LOGGER.info("BOM processed successfully in %s".formatted(formatDurationHMS(processingDurationMs)));
        if (!delayBomProcessedNotification) {
            dispatchBomProcessedNotification(ctx);
        }

        final List<ComponentVulnerabilityAnalysisEvent> vulnAnalysisEvents = createVulnAnalysisEvents(ctx, processedBom.components());
        final List<ComponentRepositoryMetaAnalysisEvent> repoMetaAnalysisEvents = createRepoMetaAnalysisEvents(processedBom.components());

        final var dispatchedEvents = new ArrayList<CompletableFuture<?>>(vulnAnalysisEvents.size() + repoMetaAnalysisEvents.size());
        dispatchedEvents.addAll(initiateVulnerabilityAnalysis(ctx, vulnAnalysisEvents));
        dispatchedEvents.addAll(initiateRepoMetaAnalysis(repoMetaAnalysisEvents));
        CompletableFuture.allOf(dispatchedEvents.toArray(new CompletableFuture[0])).join();
    }

    private record ConsumedBom(
            Project project,
            ProjectMetadata projectMetadata,
            List<Component> components,
            List<ServiceComponent> services,
            MultiValuedMap<String, String> dependencyGraph,
            Map<String, ComponentIdentity> identitiesByBomRef,
            MultiValuedMap<ComponentIdentity, String> bomRefsByIdentity
    ) {
    }

    private ConsumedBom consumeBom(final org.cyclonedx.model.Bom cdxBom) {
        // Keep track of which BOM ref points to which component identity.
        // During component and service de-duplication, we'll potentially drop
        // some BOM refs, which can break the dependency graph.
        final var identitiesByBomRef = new HashMap<String, ComponentIdentity>();

        // Component identities will change once components are persisted to the database.
        // This means we'll eventually have to update identities in "identitiesByBomRef"
        // for every BOM ref pointing to them.
        // We avoid having to iterate over, and compare, all values of "identitiesByBomRef"
        // by keeping a secondary index on identities to BOM refs.
        // Note: One identity can point to multiple BOM refs, due to component and service de-duplication.
        final var bomRefsByIdentity = new HashSetValuedHashMap<ComponentIdentity, String>();

        final ProjectMetadata projectMetadata = convertToProjectMetadata(cdxBom.getMetadata());
        final Project project = convertToProject(cdxBom.getMetadata());
        List<Component> components = new ArrayList<>();
        if (cdxBom.getMetadata() != null && cdxBom.getMetadata().getComponent() != null) {
            components.addAll(convertComponents(cdxBom.getMetadata().getComponent().getComponents()));
        }

        components.addAll(convertComponents(cdxBom.getComponents()));
        components = flatten(components, Component::getChildren, Component::setChildren);
        final int numComponentsTotal = components.size();

        List<ServiceComponent> services = convertServices(cdxBom.getServices());
        services = flatten(services, ServiceComponent::getChildren, ServiceComponent::setChildren);
        final int numServicesTotal = services.size();

        final MultiValuedMap<String, String> dependencyGraph = convertDependencyGraph(cdxBom.getDependencies());
        final int numDependencyGraphEntries = dependencyGraph.asMap().size();

        components = components.stream().filter(distinctComponentsByIdentity(identitiesByBomRef, bomRefsByIdentity)).toList();
        services = services.stream().filter(distinctServicesByIdentity(identitiesByBomRef, bomRefsByIdentity)).toList();
        LOGGER.info("""
                Consumed %d components (%d before de-duplication), %d services (%d before de-duplication), \
                and %d dependency graph entries""".formatted(components.size(), numComponentsTotal,
                services.size(), numServicesTotal, numDependencyGraphEntries));

        return new ConsumedBom(
                project,
                projectMetadata,
                components,
                services,
                dependencyGraph,
                identitiesByBomRef,
                bomRefsByIdentity
        );
    }

    private record ProcessedBom(
            Project project,
            Collection<Component> components,
            Collection<ServiceComponent> services
    ) {
    }

    private ProcessedBom processBom(final Context ctx, final ConsumedBom bom) {
        try (final var qm = new QueryManager()) {
            // Disable reachability checks on commit.
            // See https://www.datanucleus.org/products/accessplatform_4_1/jdo/performance_tuning.html
            //
            // Persistence-by-reachability is an expensive operation that involves traversing the entire
            // object graph, and potentially issuing multiple database operations in doing so.
            //
            // It also enables cascading operations (both for persisting and deleting), but we don't need them here.
            // If this circumstance ever changes, this property may be flicked to "true" again, at the cost of
            // a noticeable performance hit.
            // See:
            //   https://www.datanucleus.org/products/accessplatform_6_0/jdo/persistence.html#cascading
            //   https://www.datanucleus.org/products/accessplatform_6_0/jdo/persistence.html#_managing_relationships
            qm.getPersistenceManager().setProperty(PROPERTY_PERSISTENCE_BY_REACHABILITY_AT_COMMIT, "false");

            // Save some database round-trips by only flushing changes every FLUSH_THRESHOLD write operations.
            // See https://www.datanucleus.org/products/accessplatform_4_1/jdo/performance_tuning.html
            //
            // Note: Queries (SELECT) will always directly hit the database. Using manual flushing means
            // changes made before flush are not visible to queries. If "read-your-writes" is critical,
            // either flush immediately after making changes, or change the FlushMode back to AUTO (the default).
            // AUTO will flush all changes to the database immediately, on every single setter invocation.
            //
            // Another option would be to set FlushMode to QUERY, where flushes will be performed before *any*
            // query. Hibernate has a smart(er) behavior, where it checks if the query "touches" non-flushed
            // data, and only flushes if that's the case. DataNucleus is not as smart, and will always flush.
            // Still, QUERY may be a nice middle-ground between AUTO and MANUAL.
            //
            // BomUploadProcessingTaskTest#informWithBloatedBomTest can be used to profile the impact on large BOMs.
            qm.getPersistenceManager().setProperty(PROPERTY_FLUSH_MODE, FlushMode.MANUAL.name());

            // Prevent object fields from being unloaded upon commit.
            //
            // DataNucleus transitions objects into the "hollow" state after the transaction is committed.
            // In hollow state, all fields except the ID are unloaded. Accessing fields afterward triggers
            // one or more database queries to load them again.
            // See https://www.datanucleus.org/products/accessplatform_6_0/jdo/persistence.html#lifecycle
            qm.getPersistenceManager().setProperty(PROPERTY_RETAIN_VALUES, "true");

            return qm.runInTransaction(() -> {
                final Project persistentProject = processProject(ctx, qm, bom.project(), bom.projectMetadata());

                LOGGER.info("Processing %d components".formatted(bom.components().size()));
                final Map<ComponentIdentity, Component> persistentComponentsByIdentity =
                        processComponents(qm, persistentProject, bom.components(), bom.identitiesByBomRef(), bom.bomRefsByIdentity());

                LOGGER.info("Processing %d services".formatted(bom.services().size()));
                final Map<ComponentIdentity, ServiceComponent> persistentServicesByIdentity =
                        processServices(qm, persistentProject, bom.services(), bom.identitiesByBomRef(), bom.bomRefsByIdentity());

                LOGGER.info("Processing %d dependency graph entries".formatted(bom.dependencyGraph().asMap().size()));
                processDependencyGraph(qm, persistentProject, bom.dependencyGraph(), persistentComponentsByIdentity, bom.identitiesByBomRef());

                recordBomImport(ctx, qm, persistentProject);

                return new ProcessedBom(
                        persistentProject,
                        persistentComponentsByIdentity.values(),
                        persistentServicesByIdentity.values()
                );
            });
        }
    }

    private static Project processProject(
            final Context ctx,
            final QueryManager qm,
            final Project project,
            final ProjectMetadata projectMetadata
    ) {
        final Query<Project> query = qm.getPersistenceManager().newQuery(Project.class);
        query.setFilter("uuid == :uuid");
        query.setParameters(ctx.project.getUuid());

        final Project persistentProject;
        try {
            persistentProject = query.executeUnique();
        } finally {
            query.closeAll();
        }
        if (persistentProject == null) {
            throw new IllegalStateException("Project does not exist");
        }

        boolean hasChanged = false;
        if (project != null) {
            persistentProject.setBomRef(project.getBomRef()); // Transient
            hasChanged |= applyIfChanged(persistentProject, project, Project::getAuthor, persistentProject::setAuthor);
            hasChanged |= applyIfChanged(persistentProject, project, Project::getPublisher, persistentProject::setPublisher);
            hasChanged |= applyIfChanged(persistentProject, project, Project::getClassifier, persistentProject::setClassifier);
            hasChanged |= applyIfChanged(persistentProject, project, Project::getSupplier, persistentProject::setSupplier);
            hasChanged |= applyIfChanged(persistentProject, project, Project::getManufacturer, persistentProject::setManufacturer);
            // TODO: Currently these properties are "decoupled" from the BOM and managed directly by DT users.
            //   Perhaps there could be a flag for BOM uploads saying "use BOM properties" or something?
            // hasChanged |= applyIfChanged(persistentProject, project, Project::getGroup, persistentProject::setGroup);
            // hasChanged |= applyIfChanged(persistentProject, project, Project::getName, persistentProject::setName);
            // hasChanged |= applyIfChanged(persistentProject, project, Project::getVersion, persistentProject::setVersion);
            // hasChanged |= applyIfChanged(persistentProject, project, Project::getDescription, persistentProject::setDescription);
            hasChanged |= applyIfChanged(persistentProject, project, Project::getExternalReferences, persistentProject::setExternalReferences);
            hasChanged |= applyIfChanged(persistentProject, project, Project::getPurl, persistentProject::setPurl);
            hasChanged |= applyIfChanged(persistentProject, project, Project::getSwidTagId, persistentProject::setSwidTagId);
        }

        if (projectMetadata != null) {
            if (persistentProject.getMetadata() == null) {
                projectMetadata.setProject(persistentProject);
                qm.getPersistenceManager().makePersistent(projectMetadata);
                hasChanged = true;
            } else {
                hasChanged |= applyIfChanged(persistentProject.getMetadata(), projectMetadata, ProjectMetadata::getAuthors,
                        authors -> persistentProject.getMetadata().setAuthors(authors != null ? new ArrayList<>(authors) : null));
                hasChanged |= applyIfChanged(persistentProject.getMetadata(), projectMetadata, ProjectMetadata::getSupplier, persistentProject.getMetadata()::setSupplier);
                hasChanged |= applyIfChanged(persistentProject.getMetadata(), projectMetadata, ProjectMetadata::getTools, persistentProject.getMetadata()::setTools);
            }
        }

        if (hasChanged) {
            qm.getPersistenceManager().flush();
        }

        return persistentProject;
    }

    private static Map<ComponentIdentity, Component> processComponents(
            final QueryManager qm,
            final Project project,
            final List<Component> components,
            final Map<String, ComponentIdentity> identitiesByBomRef,
            final MultiValuedMap<ComponentIdentity, String> bomRefsByIdentity
    ) {
        assertPersistent(project, "Project must be persistent");

        // Fetch IDs of all components that exist in the project already.
        // We'll need them later to determine which components to delete.
        final Set<Long> idsOfComponentsToDelete = getAllComponentIds(qm, project, Component.class);

        // Avoid redundant queries by caching resolved licenses.
        // It is likely that if license IDs were present in a BOM,
        // they appear multiple times for different components.
        final var licenseCache = new HashMap<String, License>();

        // We support resolution of custom licenses by their name.
        // To avoid any conflicts with license IDs, cache those separately.
        final var customLicenseCache = new HashMap<String, License>();

        final var internalComponentIdentifier = new InternalComponentIdentifier();
        final var persistentComponents = new HashMap<ComponentIdentity, Component>();
        for (final Component component : components) {
            component.setInternal(internalComponentIdentifier.isInternal(component));
            resolveAndApplyLicense(qm, component, licenseCache, customLicenseCache);

            final var componentIdentity = new ComponentIdentity(component);
            Component persistentComponent;
            try {
                persistentComponent = qm.matchSingleIdentityExact(project, componentIdentity);
            } catch (JDOUserException e) {
                if (!(ExceptionUtils.getRootCause(e) instanceof QueryNotUniqueException)) {
                    throw e;
                }

                LOGGER.warn("""
                        More than one existing component match the identity %s; \
                        Proceeding with first match, others will be deleted\
                        """.formatted(componentIdentity.toJSON()));
                persistentComponent = qm.matchFirstIdentityExact(project, componentIdentity);
            }
            if (persistentComponent == null) {
                component.setProject(project);
                persistentComponent = qm.getPersistenceManager().makePersistent(component);
                persistentComponent.setNew(true); // Transient
            } else {
                persistentComponent.setBomRef(component.getBomRef()); // Transient
                applyIfChanged(persistentComponent, component, Component::getAuthor, persistentComponent::setAuthor);
                applyIfChanged(persistentComponent, component, Component::getPublisher, persistentComponent::setPublisher);
                applyIfChanged(persistentComponent, component, Component::getSupplier, persistentComponent::setSupplier);
                applyIfChanged(persistentComponent, component, Component::getClassifier, persistentComponent::setClassifier);
                applyIfChanged(persistentComponent, component, Component::getGroup, persistentComponent::setGroup);
                applyIfChanged(persistentComponent, component, Component::getName, persistentComponent::setName);
                applyIfChanged(persistentComponent, component, Component::getVersion, persistentComponent::setVersion);
                applyIfChanged(persistentComponent, component, Component::getDescription, persistentComponent::setDescription);
                applyIfChanged(persistentComponent, component, Component::getCopyright, persistentComponent::setCopyright);
                applyIfChanged(persistentComponent, component, Component::getCpe, persistentComponent::setCpe);
                applyIfChanged(persistentComponent, component, Component::getPurl, persistentComponent::setPurl);
                applyIfChanged(persistentComponent, component, Component::getSwidTagId, persistentComponent::setSwidTagId);
                applyIfChanged(persistentComponent, component, Component::getMd5, persistentComponent::setMd5);
                applyIfChanged(persistentComponent, component, Component::getSha1, persistentComponent::setSha1);
                applyIfChanged(persistentComponent, component, Component::getSha256, persistentComponent::setSha256);
                applyIfChanged(persistentComponent, component, Component::getSha384, persistentComponent::setSha384);
                applyIfChanged(persistentComponent, component, Component::getSha512, persistentComponent::setSha512);
                applyIfChanged(persistentComponent, component, Component::getSha3_256, persistentComponent::setSha3_256);
                applyIfChanged(persistentComponent, component, Component::getSha3_384, persistentComponent::setSha3_384);
                applyIfChanged(persistentComponent, component, Component::getSha3_512, persistentComponent::setSha3_512);
                applyIfChanged(persistentComponent, component, Component::getBlake2b_256, persistentComponent::setBlake2b_256);
                applyIfChanged(persistentComponent, component, Component::getBlake2b_384, persistentComponent::setBlake2b_384);
                applyIfChanged(persistentComponent, component, Component::getBlake2b_512, persistentComponent::setBlake2b_512);
                applyIfChanged(persistentComponent, component, Component::getBlake3, persistentComponent::setBlake3);
                applyIfChanged(persistentComponent, component, Component::getResolvedLicense, persistentComponent::setResolvedLicense);
                applyIfChanged(persistentComponent, component, Component::getLicense, persistentComponent::setLicense);
                applyIfChanged(persistentComponent, component, Component::getLicenseUrl, persistentComponent::setLicenseUrl);
                applyIfChanged(persistentComponent, component, Component::getLicenseExpression, persistentComponent::setLicenseExpression);
                applyIfChanged(persistentComponent, component, Component::isInternal, persistentComponent::setInternal);
                applyIfChanged(persistentComponent, component, Component::getExternalReferences, persistentComponent::setExternalReferences);

                qm.synchronizeComponentProperties(persistentComponent, component.getProperties());
                idsOfComponentsToDelete.remove(persistentComponent.getId());
            }

            // Update component identities in our Identity->BOMRef map,
            // as after persisting the components, their identities now include UUIDs.
            final var newIdentity = new ComponentIdentity(persistentComponent);
            final ComponentIdentity oldIdentity = identitiesByBomRef.put(persistentComponent.getBomRef(), newIdentity);
            for (final String bomRef : bomRefsByIdentity.get(oldIdentity)) {
                identitiesByBomRef.put(bomRef, newIdentity);
            }

            persistentComponents.put(newIdentity, persistentComponent);
        }

        qm.getPersistenceManager().flush();

        final long componentsDeleted = deleteComponentsById(qm, idsOfComponentsToDelete);
        if (componentsDeleted > 0) {
            qm.getPersistenceManager().flush();
        }

        return persistentComponents;
    }

    private static Map<ComponentIdentity, ServiceComponent> processServices(
            final QueryManager qm,
            final Project project,
            final List<ServiceComponent> services,
            final Map<String, ComponentIdentity> identitiesByBomRef,
            final MultiValuedMap<ComponentIdentity, String> bomRefsByIdentity
    ) {
        assertPersistent(project, "Project must be persistent");

        // Fetch IDs of all services that exist in the project already.
        // We'll need them later to determine which services to delete.
        final Set<Long> idsOfServicesToDelete = getAllComponentIds(qm, project, ServiceComponent.class);

        final var persistentServices = new HashMap<ComponentIdentity, ServiceComponent>();

        for (final ServiceComponent service : services) {
            final var componentIdentity = new ComponentIdentity(service);
            ServiceComponent persistentService = qm.matchServiceIdentity(project, componentIdentity);
            if (persistentService == null) {
                service.setProject(project);
                persistentService = qm.getPersistenceManager().makePersistent(service);
            } else {
                persistentService.setBomRef(service.getBomRef()); // Transient
                applyIfChanged(persistentService, service, ServiceComponent::getGroup, persistentService::setGroup);
                applyIfChanged(persistentService, service, ServiceComponent::getName, persistentService::setName);
                applyIfChanged(persistentService, service, ServiceComponent::getVersion, persistentService::setVersion);
                applyIfChanged(persistentService, service, ServiceComponent::getDescription, persistentService::setDescription);
                applyIfChanged(persistentService, service, ServiceComponent::getAuthenticated, persistentService::setAuthenticated);
                applyIfChanged(persistentService, service, ServiceComponent::getCrossesTrustBoundary, persistentService::setCrossesTrustBoundary);
                applyIfChanged(persistentService, service, ServiceComponent::getExternalReferences, persistentService::setExternalReferences);
                applyIfChanged(persistentService, service, ServiceComponent::getProvider, persistentService::setProvider);
                applyIfChanged(persistentService, service, ServiceComponent::getData, persistentService::setData);
                applyIfChanged(persistentService, service, ServiceComponent::getEndpoints, persistentService::setEndpoints);
                idsOfServicesToDelete.remove(persistentService.getId());
            }

            // Update component identities in our Identity->BOMRef map,
            // as after persisting the services, their identities now include UUIDs.
            final var newIdentity = new ComponentIdentity(persistentService);
            final ComponentIdentity oldIdentity = identitiesByBomRef.put(service.getBomRef(), newIdentity);
            for (final String bomRef : bomRefsByIdentity.get(oldIdentity)) {
                identitiesByBomRef.put(bomRef, newIdentity);
            }

            persistentServices.put(newIdentity, persistentService);
        }

        qm.getPersistenceManager().flush();

        final long servicesDeleted = deleteServicesById(qm, idsOfServicesToDelete);
        if (servicesDeleted > 0) {
            qm.getPersistenceManager().flush();
        }

        return persistentServices;
    }

    private void processDependencyGraph(
            final QueryManager qm,
            final Project project,
            final MultiValuedMap<String, String> dependencyGraph,
            final Map<ComponentIdentity, Component> componentsByIdentity,
            final Map<String, ComponentIdentity> identitiesByBomRef
    ) {
        assertPersistent(project, "Project must be persistent");

        if (project.getBomRef() != null) {
            final Collection<String> directDependencyBomRefs = dependencyGraph.get(project.getBomRef());
            if (directDependencyBomRefs == null || directDependencyBomRefs.isEmpty()) {
                LOGGER.warn("""
                        The dependency graph has %d entries, but the project (metadata.component node of the BOM) \
                        is not one of them; Graph will be incomplete because it is not possible to determine its root\
                        """.formatted(dependencyGraph.size()));
            }
            final String directDependenciesJson = resolveDirectDependenciesJson(project.getBomRef(), directDependencyBomRefs, identitiesByBomRef);
            if (!Objects.equals(directDependenciesJson, project.getDirectDependencies())) {
                project.setDirectDependencies(directDependenciesJson);
                qm.getPersistenceManager().flush();
            }
        } else {
            // Make sure we don't retain stale data from previous BOM uploads.
            if (project.getDirectDependencies() != null) {
                project.setDirectDependencies(null);
                qm.getPersistenceManager().flush();
            }
        }

        for (final Map.Entry<String, ComponentIdentity> entry : identitiesByBomRef.entrySet()) {
            final String componentBomRef = entry.getKey();
            final Collection<String> directDependencyBomRefs = dependencyGraph.get(componentBomRef);
            final String directDependenciesJson = resolveDirectDependenciesJson(componentBomRef, directDependencyBomRefs, identitiesByBomRef);

            final ComponentIdentity dependencyIdentity = identitiesByBomRef.get(entry.getKey());
            final Component component = componentsByIdentity.get(dependencyIdentity);
            // TODO: Check servicesByIdentity when persistentComponent is null
            //   We do not currently store directDependencies for ServiceComponent
            if (component != null) {
                assertPersistent(component, "Component must be persistent");
                if (!Objects.equals(directDependenciesJson, component.getDirectDependencies())) {
                    component.setDirectDependencies(directDependenciesJson);
                }
            } else {
                LOGGER.warn("""
                        Unable to resolve component identity %s to a persistent component; \
                        As a result, the dependency graph will likely be incomplete\
                        """.formatted(dependencyIdentity.toJSON()));
            }
        }

        qm.getPersistenceManager().flush();
    }

    private static void recordBomImport(final Context ctx, final QueryManager qm, final Project project) {
        assertPersistent(project, "Project must be persistent");

        final var bomImportDate = new Date();

        final var bom = new Bom();
        bom.setProject(project);
        bom.setBomFormat(ctx.bomFormat);
        bom.setSpecVersion(ctx.bomSpecVersion);
        bom.setSerialNumber(ctx.bomSerialNumber);
        bom.setBomVersion(ctx.bomVersion);
        bom.setImported(bomImportDate);
        bom.setGenerated(ctx.bomTimestamp);
        qm.getPersistenceManager().makePersistent(bom);

        project.setLastBomImport(bomImportDate);
        project.setLastBomImportFormat("%s %s".formatted(ctx.bomFormat.getFormatShortName(), ctx.bomSpecVersion));
    }

    private String resolveDirectDependenciesJson(
            final String dependencyBomRef,
            final Collection<String> directDependencyBomRefs,
            final Map<String, ComponentIdentity> identitiesByBomRef
    ) {
        if (directDependencyBomRefs == null || directDependencyBomRefs.isEmpty()) {
            return null;
        }

        final var jsonDependencies = new JSONArray();
        for (final String directDependencyBomRef : directDependencyBomRefs) {
            final ComponentIdentity directDependencyIdentity = identitiesByBomRef.get(directDependencyBomRef);
            if (directDependencyIdentity != null) {
                jsonDependencies.put(directDependencyIdentity.toJSON());
            } else {
                LOGGER.warn("""
                        Unable to resolve BOM ref %s to a component identity while processing direct \
                        dependencies of BOM ref %s; As a result, the dependency graph will likely be incomplete\
                        """.formatted(dependencyBomRef, directDependencyBomRef));
            }
        }

        return jsonDependencies.isEmpty() ? null : jsonDependencies.toString();
    }

    private static long deleteComponentsById(final QueryManager qm, final Collection<Long> componentIds) {
        if (componentIds.isEmpty()) {
            return 0;
        }

        final PersistenceManager pm = qm.getPersistenceManager();
        LOGGER.info("Deleting %d component(s) that are no longer part of the project".formatted(componentIds.size()));
        pm.newQuery(Query.JDOQL, "DELETE FROM org.dependencytrack.model.AnalysisComment WHERE :ids.contains(analysis.component.id)").execute(componentIds);
        pm.newQuery(Query.JDOQL, "DELETE FROM org.dependencytrack.model.Analysis WHERE :ids.contains(component.id)").execute(componentIds);
        pm.newQuery(Query.JDOQL, "DELETE FROM org.dependencytrack.model.ViolationAnalysisComment WHERE :ids.contains(violationAnalysis.component.id)").execute(componentIds);
        pm.newQuery(Query.JDOQL, "DELETE FROM org.dependencytrack.model.ViolationAnalysis WHERE :ids.contains(component.id)").execute(componentIds);
        pm.newQuery(Query.JDOQL, "DELETE FROM org.dependencytrack.model.DependencyMetrics WHERE :ids.contains(component.id)").execute(componentIds);
        pm.newQuery(Query.JDOQL, "DELETE FROM org.dependencytrack.model.FindingAttribution WHERE :ids.contains(component.id)").execute(componentIds);
        pm.newQuery(Query.JDOQL, "DELETE FROM org.dependencytrack.model.PolicyViolation WHERE :ids.contains(component.id)").execute(componentIds);
        pm.newQuery(Query.JDOQL, "DELETE FROM org.dependencytrack.model.IntegrityAnalysis WHERE :ids.contains(component.id)").execute(componentIds);
        return pm.newQuery(Component.class, ":ids.contains(id)").deletePersistentAll(componentIds);
    }

    private static long deleteServicesById(final QueryManager qm, final Collection<Long> serviceIds) {
        if (serviceIds.isEmpty()) {
            return 0;
        }

        final PersistenceManager pm = qm.getPersistenceManager();
        LOGGER.info("Deleting %d service(s) that are no longer part of the project".formatted(serviceIds.size()));
        return pm.newQuery(ServiceComponent.class, ":ids.contains(id)").deletePersistentAll(serviceIds);
    }

    private static void resolveAndApplyLicense(
            final QueryManager qm,
            final Component component,
            final Map<String, License> licenseCache,
            final Map<String, License> customLicenseCache
    ) {
        // CycloneDX components can declare multiple licenses, but we currently
        // only support one. We assume that the licenseCandidates list is ordered
        // by priority, and simply take the first resolvable candidate.
        for (final org.cyclonedx.model.License licenseCandidate : component.getLicenseCandidates()) {
            if (isNotBlank(licenseCandidate.getId())) {
                final License resolvedLicense = licenseCache.computeIfAbsent(licenseCandidate.getId(),
                        licenseId -> resolveLicense(qm, licenseId));
                if (resolvedLicense != License.UNRESOLVED) {
                    component.setResolvedLicense(resolvedLicense);
                    component.setLicenseUrl(trimToNull(licenseCandidate.getUrl()));
                    break;
                }
            }

            if (isNotBlank(licenseCandidate.getName())) {
                final License resolvedLicense = licenseCache.computeIfAbsent(licenseCandidate.getName(),
                        licenseName -> resolveLicense(qm, licenseName));
                if (resolvedLicense != License.UNRESOLVED) {
                    component.setResolvedLicense(resolvedLicense);
                    component.setLicenseUrl(trimToNull(licenseCandidate.getUrl()));
                    break;
                }

                final License resolvedCustomLicense = customLicenseCache.computeIfAbsent(licenseCandidate.getName(),
                        licenseName -> resolveCustomLicense(qm, licenseName));
                if (resolvedCustomLicense != License.UNRESOLVED) {
                    component.setResolvedLicense(resolvedCustomLicense);
                    component.setLicenseUrl(trimToNull(licenseCandidate.getUrl()));
                    break;
                }
            }
        }

        // If we were unable to resolve any license by its ID, at least
        // populate the license name. Again assuming order by priority.
        if (component.getResolvedLicense() == null) {
            component.getLicenseCandidates().stream()
                    .filter(license -> isNotBlank(license.getName()))
                    .findFirst()
                    .ifPresent(license -> {
                        component.setLicense(trim(license.getName()));
                        component.setLicenseUrl(trimToNull(license.getUrl()));
                    });
        }
    }

    private static License resolveLicense(final QueryManager qm, final String licenseIdOrName) {
        final Query<License> query = qm.getPersistenceManager().newQuery(License.class);
        query.setFilter("licenseId == :licenseIdOrName || name == :licenseIdOrName");
        query.setNamedParameters(Map.of("licenseIdOrName", licenseIdOrName));
        try {
            final License license = query.executeUnique();
            return license != null ? license : License.UNRESOLVED;
        } finally {
            query.closeAll();
        }
    }

    private static License resolveCustomLicense(final QueryManager qm, final String licenseName) {
        final Query<License> query = qm.getPersistenceManager().newQuery(License.class);
        query.setFilter("name == :name && customLicense == true");
        query.setParameters(licenseName);
        try {
            final License license = query.executeUnique();
            return license != null ? license : License.UNRESOLVED;
        } finally {
            query.closeAll();
        }
    }

    private static <T> Set<Long> getAllComponentIds(final QueryManager qm, final Project project, final Class<T> clazz) {
        final Query<T> query = qm.getPersistenceManager().newQuery(clazz);
        query.setFilter("project == :project");
        query.setParameters(project);
        query.setResult("id");

        try {
            return new HashSet<>(query.executeResultList(Long.class));
        } finally {
            query.closeAll();
        }
    }

    private static Predicate<Component> distinctComponentsByIdentity(
            final Map<String, ComponentIdentity> identitiesByBomRef,
            final MultiValuedMap<ComponentIdentity, String> bomRefsByIdentity
    ) {
        final var identitiesSeen = new HashSet<ComponentIdentity>();
        return component -> {
            final var componentIdentity = new ComponentIdentity(component);

            final boolean isBomRefUnique = identitiesByBomRef.putIfAbsent(component.getBomRef(), componentIdentity) == null;
            if (!isBomRefUnique) {
                LOGGER.warn("""
                        BOM ref %s is associated with multiple components in the BOM; \
                        BOM refs are required to be unique; Please report this to the vendor \
                        of the tool that generated the BOM""".formatted(component.getBomRef()));
            }

            bomRefsByIdentity.put(componentIdentity, component.getBomRef());

            final boolean isSeenBefore = !identitiesSeen.add(componentIdentity);
            if (LOGGER.isDebugEnabled() && isSeenBefore) {
                LOGGER.debug("Filtering component with BOM ref %s and identity %s due to duplicate identity"
                        .formatted(component.getBomRef(), componentIdentity.toJSON()));
            }

            return !isSeenBefore;
        };
    }

    private static Predicate<ServiceComponent> distinctServicesByIdentity(
            final Map<String, ComponentIdentity> identitiesByBomRef,
            final MultiValuedMap<ComponentIdentity, String> bomRefsByIdentity
    ) {
        final var identitiesSeen = new HashSet<ComponentIdentity>();
        return service -> {
            final var componentIdentity = new ComponentIdentity(service);
            identitiesByBomRef.putIfAbsent(service.getBomRef(), componentIdentity);
            bomRefsByIdentity.put(componentIdentity, service.getBomRef());
            final boolean isSeenBefore = !identitiesSeen.add(componentIdentity);
            if (LOGGER.isDebugEnabled() && isSeenBefore) {
                LOGGER.debug("Filtering service with BOM ref %s and identity %s due to duplicate identity"
                        .formatted(service.getBomRef(), componentIdentity.toJSON()));
            }

            return !isSeenBefore;
        };
    }

    private static void startBomConsumptionWorkflowStep(final Context ctx) {
        // TODO: This should be a single UPDATE query.
        try (final var qm = new QueryManager()) {
            qm.runInTransaction(() -> {
                final WorkflowState bomConsumptionState =
                        qm.getWorkflowStateByTokenAndStep(ctx.token, WorkflowStep.BOM_CONSUMPTION);
                bomConsumptionState.setStartedAt(Date.from(Instant.now()));
            });
        }
    }

    private static void startBomProcessingWorkflowStep(final Context ctx) {
        // TODO: This should be a batched UPDATE query.
        try (var qm = new QueryManager()) {
            qm.runInTransaction(() -> {
                final WorkflowState bomConsumptionState =
                        qm.getWorkflowStateByTokenAndStep(ctx.token, WorkflowStep.BOM_CONSUMPTION);
                bomConsumptionState.setStatus(WorkflowStatus.COMPLETED);
                bomConsumptionState.setUpdatedAt(Date.from(Instant.now()));

                final WorkflowState bomProcessingState =
                        qm.getWorkflowStateByTokenAndStep(ctx.token, WorkflowStep.BOM_PROCESSING);
                bomProcessingState.setStartedAt(Date.from(Instant.now()));
            });
        }
    }

    private static void completeBomProcessingWorkflowStep(final Context ctx) {
        // TODO: This should be a single UPDATE query.
        try (final var qm = new QueryManager()) {
            qm.runInTransaction(() -> {
                final WorkflowState bomProcessingState =
                        qm.getWorkflowStateByTokenAndStep(ctx.token, WorkflowStep.BOM_PROCESSING);
                bomProcessingState.setStatus(WorkflowStatus.COMPLETED);
                bomProcessingState.setUpdatedAt(new Date());
            });
        }
    }

    private static void failWorkflowStepAndCancelDescendants(
            final Context ctx,
            final WorkflowStep step,
            final Throwable failureCause
    ) {
        try (var qm = new QueryManager()) {
            qm.runInTransaction(() -> {
                final var now = new Date();
                final WorkflowState workflowState = qm.getWorkflowStateByTokenAndStep(ctx.token, step);
                workflowState.setStatus(WorkflowStatus.FAILED);
                workflowState.setFailureReason(failureCause.getMessage());
                workflowState.setUpdatedAt(now);
                qm.updateAllDescendantStatesOfParent(workflowState, WorkflowStatus.CANCELLED, now);
            });
        }
    }

    private List<CompletableFuture<?>> initiateVulnerabilityAnalysis(
            final Context ctx,
            final Collection<ComponentVulnerabilityAnalysisEvent> events
    ) {
        if (events.isEmpty()) {
            // No components to be sent for vulnerability analysis.
            // If the BOM_PROCESSED notification was delayed, dispatch it now.
            if (delayBomProcessedNotification) {
                dispatchBomProcessedNotification(ctx);
            }

            try (final var qm = new QueryManager()) {
                qm.runInTransaction(() -> {
                    final WorkflowState vulnAnalysisWorkflowState =
                            qm.getWorkflowStateByTokenAndStep(ctx.token, WorkflowStep.VULN_ANALYSIS);
                    vulnAnalysisWorkflowState.setStatus(WorkflowStatus.NOT_APPLICABLE);
                    vulnAnalysisWorkflowState.setUpdatedAt(new Date());

                    final WorkflowState policyEvalWorkflowState =
                            qm.getWorkflowStateByTokenAndStep(ctx.token, WorkflowStep.POLICY_EVALUATION);
                    policyEvalWorkflowState.setStatus(WorkflowStatus.NOT_APPLICABLE);
                    policyEvalWorkflowState.setUpdatedAt(new Date());
                });
            }

            // Trigger project metrics update no matter if vuln analysis is applicable or not.
            final ChainableEvent metricsUpdateEvent = new ProjectMetricsUpdateEvent(ctx.project.getUuid());
            metricsUpdateEvent.setChainIdentifier(ctx.token);
            Event.dispatch(metricsUpdateEvent);

            return Collections.emptyList();
        }

        try (final var qm = new QueryManager()) {
            // TODO: Creation of the scan, and starting of the workflow step, should happen in the same transaction.
            //   Requires a bit of refactoring in QueryManager#createVulnerabilityScan.

            qm.createVulnerabilityScan(
                    TargetType.PROJECT,
                    ctx.project.getUuid(),
                    ctx.token.toString(),
                    events.size()
            );

            qm.runInTransaction(() -> {
                final WorkflowState vulnAnalysisWorkflowState =
                        qm.getWorkflowStateByTokenAndStep(ctx.token, WorkflowStep.VULN_ANALYSIS);
                vulnAnalysisWorkflowState.setStartedAt(new Date());
            });
        }

        return events.stream()
                .<CompletableFuture<?>>map(event -> kafkaEventDispatcher.dispatchEvent(event).whenComplete(
                        (ignored, throwable) -> {
                            if (throwable != null) {
                                // Include context in the log message to make log correlation easier.
                                LOGGER.error("Failed to produce %s to Kafka".formatted(event), throwable);
                            }
                        }
                ))
                .toList();
    }

    private List<CompletableFuture<?>> initiateRepoMetaAnalysis(final Collection<ComponentRepositoryMetaAnalysisEvent> events) {
        return events.stream()
                .<CompletableFuture<?>>map(event -> kafkaEventDispatcher.dispatchEvent(event).whenComplete(
                        (ignored, throwable) -> {
                            if (throwable != null) {
                                // Include context in the log message to make log correlation easier.
                                LOGGER.error("Failed to produce %s to Kafka".formatted(event), throwable);
                            }
                        }
                ))
                .toList();
    }

    private void dispatchBomConsumedNotification(final Context ctx) {
        kafkaEventDispatcher.dispatchNotification(new Notification()
                .scope(NotificationScope.PORTFOLIO)
                .group(NotificationGroup.BOM_CONSUMED)
                .level(NotificationLevel.INFORMATIONAL)
                .title(NotificationConstants.Title.BOM_CONSUMED)
                .content("A %s BOM was consumed and will be processed".formatted(ctx.bomFormat.getFormatShortName()))
                .subject(new BomConsumedOrProcessed(ctx.token, ctx.project, /* bom */ "(Omitted)", ctx.bomFormat, ctx.bomSpecVersion)));
    }

    private void dispatchBomProcessedNotification(final Context ctx) {
        kafkaEventDispatcher.dispatchNotification(new Notification()
                .scope(NotificationScope.PORTFOLIO)
                .group(NotificationGroup.BOM_PROCESSED)
                .level(NotificationLevel.INFORMATIONAL)
                .title(NotificationConstants.Title.BOM_PROCESSED)
                .content("A %s BOM was processed".formatted(ctx.bomFormat.getFormatShortName()))
                // FIXME: Add reference to BOM after we have dedicated BOM server
                .subject(new BomConsumedOrProcessed(ctx.token, ctx.project, /* bom */ "(Omitted)", ctx.bomFormat, ctx.bomSpecVersion)));
    }

    private void dispatchBomProcessingFailedNotification(final Context ctx, final Throwable throwable) {
        kafkaEventDispatcher.dispatchNotification(new Notification()
                .scope(NotificationScope.PORTFOLIO)
                .group(NotificationGroup.BOM_PROCESSING_FAILED)
                .level(NotificationLevel.ERROR)
                .title(NotificationConstants.Title.BOM_PROCESSING_FAILED)
                .content("An error occurred while processing a BOM")
                // TODO: Look into adding more fields to BomProcessingFailed, to also cover serial number, version, etc.
                // FIXME: Add reference to BOM after we have dedicated BOM server
                .subject(new BomProcessingFailed(ctx.token, ctx.project, /* bom */ "(Omitted)", throwable.getMessage(), ctx.bomFormat, ctx.bomSpecVersion)));
    }

    private static List<ComponentVulnerabilityAnalysisEvent> createVulnAnalysisEvents(
            final Context ctx,
            final Collection<Component> components
    ) {
        return components.stream()
                .map(component -> new ComponentVulnerabilityAnalysisEvent(
                        ctx.token,
                        component,
                        VulnerabilityAnalysisLevel.BOM_UPLOAD_ANALYSIS,
                        component.isNew()
                ))
                .toList();
    }

    private static List<ComponentRepositoryMetaAnalysisEvent> createRepoMetaAnalysisEvents(final Collection<Component> components) {
        final var events = new ArrayList<ComponentRepositoryMetaAnalysisEvent>(components.size());
        // TODO: This should be more efficient (https://github.com/DependencyTrack/hyades/issues/1306)

        try (final var qm = new QueryManager()) {
            qm.getPersistenceManager().setProperty(PROPERTY_PERSISTENCE_BY_REACHABILITY_AT_COMMIT, "false");
            qm.getPersistenceManager().setProperty(PROPERTY_RETAIN_VALUES, "true");

            for (final Component component : components) {
                if (component.getPurl() == null) {
                    continue;
                }

                if (!SUPPORTED_PACKAGE_URLS_FOR_INTEGRITY_CHECK.contains(component.getPurl().getType())) {
                    events.add(new ComponentRepositoryMetaAnalysisEvent(
                            /* componentUuid */ null,
                            component.getPurlCoordinates().toString(),
                            component.isInternal(),
                            FETCH_META_LATEST_VERSION
                    ));
                    continue;
                }

                final boolean shouldFetchIntegrityData = qm.runInTransaction(() -> prepareIntegrityMetaComponent(qm, component));
                if (shouldFetchIntegrityData) {
                    events.add(new ComponentRepositoryMetaAnalysisEvent(
                            component.getUuid(),
                            component.getPurl().toString(),
                            component.isInternal(),
                            FETCH_META_INTEGRITY_DATA_AND_LATEST_VERSION
                    ));
                } else {
                    // If integrity metadata was fetched recently, we don't want to fetch it again
                    // as it's unlikely to change frequently. Fall back to fetching only the latest
                    // version information.
                    events.add(new ComponentRepositoryMetaAnalysisEvent(
                            /* componentUuid */ null,
                            component.getPurlCoordinates().toString(),
                            component.isInternal(),
                            FETCH_META_LATEST_VERSION
                    ));
                }
            }
        }

        return events;
    }

    private static boolean prepareIntegrityMetaComponent(final QueryManager qm, final Component component) {
        final IntegrityMetaComponent integrityMetaComponent = qm.getIntegrityMetaComponent(component.getPurlCoordinates().toString());
        if (integrityMetaComponent == null) {
            qm.createIntegrityMetaHandlingConflict(AbstractMetaHandler.createIntegrityMetaComponent(component.getPurlCoordinates().toString()));
            return true;
        } else if (integrityMetaComponent.getStatus() == null
                || (integrityMetaComponent.getStatus() == FetchStatus.IN_PROGRESS
                && (Date.from(Instant.now()).getTime() - integrityMetaComponent.getLastFetch().getTime()) > TIME_SPAN)) {
            integrityMetaComponent.setLastFetch(Date.from(Instant.now()));
            return true;
        } else if (integrityMetaComponent.getStatus() == FetchStatus.PROCESSED || integrityMetaComponent.getStatus() == FetchStatus.NOT_AVAILABLE) {
            qm.getPersistenceManager().makeTransient(integrityMetaComponent);
            EventService.getInstance().publish(new IntegrityAnalysisEvent(component.getUuid(), integrityMetaComponent));
            return false;
        }
        //don't send event because integrity metadata would be sent recently and don't want to send again
        return false;
    }

    private static WaitingLockConfiguration createLockConfiguration(final Context ctx) {
        return new WaitingLockConfiguration(
                /* createdAt */ Instant.now(),
                /* name */ "%s-%s".formatted(BomUploadProcessingTask.class.getSimpleName(), ctx.project.getUuid()),
                /* lockAtMostFor */ Duration.ofMinutes(5),
                /* lockAtLeastFor */ Duration.ZERO,
                /* pollInterval */ Duration.ofMillis(100),
                /* waitTimeout */ Duration.ofMinutes(5)
        );
    }

}
