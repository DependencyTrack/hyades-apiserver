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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.tasks;

import alpine.common.logging.Logger;
import alpine.common.metrics.Metrics;
import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import alpine.notification.Notification;
import alpine.notification.NotificationLevel;
import io.micrometer.core.instrument.Timer;
import org.cyclonedx.BomParserFactory;
import org.cyclonedx.exception.ParseException;
import org.cyclonedx.model.Dependency;
import org.cyclonedx.parsers.Parser;
import org.datanucleus.PropertyNames;
import org.datanucleus.flush.FlushMode;
import org.dependencytrack.event.BomUploadEvent;
import org.dependencytrack.event.ComponentRepositoryMetaAnalysisEvent;
import org.dependencytrack.event.ComponentVulnerabilityAnalysisEvent;
import org.dependencytrack.event.kafka.KafkaEventDispatcher;
import org.dependencytrack.model.Bom;
import org.dependencytrack.model.Classifier;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ComponentIdentity;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.License;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ServiceComponent;
import org.dependencytrack.model.VulnerabilityAnalysisLevel;
import org.dependencytrack.model.VulnerabilityScan.TargetType;
import org.dependencytrack.notification.NotificationConstants;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.notification.vo.BomConsumedOrProcessed;
import org.dependencytrack.notification.vo.BomProcessingFailed;
import org.dependencytrack.parser.cyclonedx.util.ModelConverter;
import org.dependencytrack.persistence.QueryManager;
import org.json.JSONArray;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import javax.jdo.Transaction;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Predicate;

import static org.dependencytrack.parser.cyclonedx.ModelConverterX.convertComponents;
import static org.dependencytrack.parser.cyclonedx.ModelConverterX.convertServices;
import static org.dependencytrack.parser.cyclonedx.ModelConverterX.convertToProject;
import static org.dependencytrack.parser.cyclonedx.ModelConverterX.flattenComponents;
import static org.dependencytrack.parser.cyclonedx.ModelConverterX.flattenServices;
import static org.dependencytrack.util.InternalComponentIdentificationUtil.isInternalComponent;
import static org.dependencytrack.util.PersistenceUtil.applyIfChanged;

/**
 * Subscriber task that performs processing of bill-of-material (bom)
 * when it is uploaded.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public class BomUploadProcessingTask implements Subscriber {

    private static final Logger LOGGER = Logger.getLogger(BomUploadProcessingTask.class);
    static final Timer TIMER = Timer.builder("bom_upload_processing")
            .description("Time taken to process / ingest uploaded Bill of Materials")
            .register(Metrics.getRegistry());

    private final KafkaEventDispatcher kafkaEventDispatcher;

    public BomUploadProcessingTask() {
        this(new KafkaEventDispatcher());
    }

    BomUploadProcessingTask(final KafkaEventDispatcher kafkaEventDispatcher) {
        this.kafkaEventDispatcher = kafkaEventDispatcher;
    }

    void process(final BomUploadEvent event) {
        LOGGER.info("Consuming CycloneDX BOM uploaded to project: " + event.getProjectUuid());
        final org.cyclonedx.model.Bom cdxBom;
        try {
            cdxBom = parseBom(event);
        } catch (IOException | ParseException e) {
            // TODO: Send BOM_PROCESSING_FAILED notification
            throw new RuntimeException(e);
        }

        final Project metadataComponent;
        if (cdxBom.getMetadata() != null && cdxBom.getMetadata().getComponent() != null) {
            metadataComponent = convertToProject(cdxBom.getMetadata().getComponent());
        } else {
            metadataComponent = null;
        }

        // Keep track of which BOM ref points to which component identity.
        //
        // During component and service de-duplication we'll potentially drop
        // some BOM refs, which can break the dependency graph.
        final var componentIdentityBomRefs = new HashMap<String, ComponentIdentity>();

        final List<Component> components = flattenComponents(convertComponents(cdxBom.getComponents())).stream()
                .filter(distinctComponentByIdentity(componentIdentityBomRefs))
                .toList();
        final List<ServiceComponent> serviceComponents = flattenServices(convertServices(cdxBom.getServices())).stream()
                .filter(distinctServiceByIdentity(componentIdentityBomRefs))
                .toList();

        final var vulnAnalysisEvents = new ArrayList<ComponentVulnerabilityAnalysisEvent>();

        try (final var qm = new QueryManager()) {
            final PersistenceManager pm = qm.getPersistenceManager();
            pm.setProperty(PropertyNames.PROPERTY_PERSISTENCE_BY_REACHABILITY_AT_COMMIT, "false");

            // Save some database round-trips by only flushing changes every "flushThreshold" write operations.
            // See https://www.datanucleus.org/products/accessplatform_4_1/jdo/performance_tuning.html
            pm.setProperty(PropertyNames.PROPERTY_FLUSH_MODE, FlushMode.MANUAL.name());
            final int flushThreshold = 1000; // Number of changes until a flush should be triggered
            int numFlushableChanges = 0; // Number of changes to be flushed

            LOGGER.info("""
                    Processing %d components and %d services from CycloneDX BOM uploaded to project: %s"""
                    .formatted(components.size(), serviceComponents.size(), event.getProjectUuid()));

            final Transaction trx = pm.currentTransaction();
            try {
                trx.begin();

                final Query<Project> projectQuery = pm.newQuery(Project.class);
                projectQuery.setFilter("uuid == :uuid");
                projectQuery.setParameters(event.getProjectUuid());
                final Project project = executeUniqueQuery(projectQuery);
                if (project == null) {
                    // TODO: Send BOM_PROCESSING_FAILED notification
                    throw new NoSuchElementException("Project with UUID " + event.getProjectUuid() + " could not be found");
                }

                // TODO: Move into separate method
                if (metadataComponent != null) {
                    boolean projectChanged = false;
                    projectChanged |= applyIfChanged(project, metadataComponent, Project::getAuthor, project::setAuthor);
                    projectChanged |= applyIfChanged(project, metadataComponent, Project::getPublisher, project::setPublisher);
                    projectChanged |= applyIfChanged(project, metadataComponent, Project::getClassifier, project::setClassifier);
                    // TODO: Currently these properties are "decoupled" from the BOM and managed directly by DT users.
                    // Perhaps there could be a flag for BOM uploads saying "use BOM properties" or something?
                    // projectChanged |= applyIfChanged(project, metadataComponent, Project::getGroup, project::setGroup);
                    // projectChanged |= applyIfChanged(project, metadataComponent, Project::getName, project::setName);
                    // projectChanged |= applyIfChanged(project, metadataComponent, Project::getVersion, project::setVersion);
                    // projectChanged |= applyIfChanged(project, metadataComponent, Project::getDescription, project::setDescription);
                    // projectChanged |= applyIfChanged(project, metadataComponent, Project::getExternalReferences, project::setExternalReferences);
                    projectChanged |= applyIfChanged(project, metadataComponent, Project::getPurl, project::setPurl);
                    projectChanged |= applyIfChanged(project, metadataComponent, Project::getSwidTagId, project::setSwidTagId);
                    if (projectChanged) {
                        pm.flush();
                    }
                }

                // Fetch IDs of all components that exist in the project already.
                // We'll need them later to determine which components to delete.
                final Query<Component> oldComponentIdsQuery = pm.newQuery(Component.class);
                oldComponentIdsQuery.setFilter("project == :project");
                oldComponentIdsQuery.setParameters(project);
                oldComponentIdsQuery.setResult("id");
                final Set<Long> oldComponentIds = new HashSet<>(executeResultListQuery(oldComponentIdsQuery, Long.class));

                // Avoid redundant queries by caching resolved licenses.
                final var licenseCache = new HashMap<String, License>();

                // TODO: Move into separate method
                final var persistentComponents = new HashMap<ComponentIdentity, Component>();
                for (final Component component : components) {
                    component.setInternal(isInternalComponent(component, qm));

                    // Try to resolve the license by its ID.
                    // Note: licenseId is a transient field of Component and will not survive this transaction.
                    if (component.getLicenseId() != null) {
                        if (licenseCache.containsKey(component.getLicenseId())) {
                            component.setResolvedLicense(licenseCache.get(component.getLicenseId()));
                        } else {
                            final Query<License> licenseQuery = pm.newQuery(License.class);
                            licenseQuery.setFilter("licenseId == :licenseId");
                            licenseQuery.setParameters(component.getLicenseId());
                            final License license = executeUniqueQuery(licenseQuery);
                            component.setResolvedLicense(license);
                            licenseCache.put(component.getLicenseId(), license);
                        }
                    }

                    final boolean isNewOrUpdated;
                    final var componentIdentity = new ComponentIdentity(component);
                    Component persistentComponent = qm.matchSingleIdentity(project, componentIdentity);
                    if (persistentComponent == null) {
                        component.setProject(project);
                        persistentComponent = pm.makePersistent(component);
                        isNewOrUpdated = true;

                        // TODO: Mark as "new"
                    } else {
                        // Only call setters when values actually changed. Otherwise, we'll trigger lots of unnecessary
                        // database calls.
                        var changed = false;
                        changed |= applyIfChanged(persistentComponent, component, Component::getAuthor, persistentComponent::setAuthor);
                        changed |= applyIfChanged(persistentComponent, component, Component::getPublisher, persistentComponent::setPublisher);
                        changed |= applyIfChanged(persistentComponent, component, Component::getClassifier, persistentComponent::setClassifier);
                        changed |= applyIfChanged(persistentComponent, component, Component::getGroup, persistentComponent::setGroup);
                        changed |= applyIfChanged(persistentComponent, component, Component::getName, persistentComponent::setName);
                        changed |= applyIfChanged(persistentComponent, component, Component::getVersion, persistentComponent::setVersion);
                        changed |= applyIfChanged(persistentComponent, component, Component::getDescription, persistentComponent::setDescription);
                        changed |= applyIfChanged(persistentComponent, component, Component::getCopyright, persistentComponent::setCopyright);
                        changed |= applyIfChanged(persistentComponent, component, Component::getCpe, persistentComponent::setCpe);
                        changed |= applyIfChanged(persistentComponent, component, Component::getPurl, persistentComponent::setPurl);
                        changed |= applyIfChanged(persistentComponent, component, Component::getSwidTagId, persistentComponent::setSwidTagId);
                        changed |= applyIfChanged(persistentComponent, component, Component::getMd5, persistentComponent::setMd5);
                        changed |= applyIfChanged(persistentComponent, component, Component::getSha1, persistentComponent::setSha1);
                        changed |= applyIfChanged(persistentComponent, component, Component::getSha256, persistentComponent::setSha256);
                        changed |= applyIfChanged(persistentComponent, component, Component::getSha384, persistentComponent::setSha384);
                        changed |= applyIfChanged(persistentComponent, component, Component::getSha512, persistentComponent::setSha512);
                        changed |= applyIfChanged(persistentComponent, component, Component::getSha3_256, persistentComponent::setSha3_256);
                        changed |= applyIfChanged(persistentComponent, component, Component::getSha3_384, persistentComponent::setSha3_384);
                        changed |= applyIfChanged(persistentComponent, component, Component::getSha3_512, persistentComponent::setSha3_512);
                        changed |= applyIfChanged(persistentComponent, component, Component::getBlake2b_256, persistentComponent::setBlake2b_256);
                        changed |= applyIfChanged(persistentComponent, component, Component::getBlake2b_384, persistentComponent::setBlake2b_384);
                        changed |= applyIfChanged(persistentComponent, component, Component::getBlake2b_512, persistentComponent::setBlake2b_512);
                        changed |= applyIfChanged(persistentComponent, component, Component::getBlake3, persistentComponent::setBlake3);
                        changed |= applyIfChanged(persistentComponent, component, Component::getResolvedLicense, persistentComponent::setResolvedLicense);
                        changed |= applyIfChanged(persistentComponent, component, Component::getLicense, persistentComponent::setLicense);
                        changed |= applyIfChanged(persistentComponent, component, Component::getLicenseUrl, persistentComponent::setLicenseUrl);
                        changed |= applyIfChanged(persistentComponent, component, Component::isInternal, persistentComponent::setInternal);
                        isNewOrUpdated = changed;

                        // BOM ref is transient and thus doesn't count towards the changed status.
                        persistentComponent.setBomRef(component.getBomRef());

                        // Exclude from components to delete.
                        if (!oldComponentIds.isEmpty()) {
                            oldComponentIds.remove(persistentComponent.getId());
                        }
                    }

                    // Update component identities in our Identity->BOMRef map,
                    // as after persisting the components, their identities now include UUIDs.
                    // Applications like the frontend rely on the UUIDs being there.
                    final var newComponentIdentity = new ComponentIdentity(persistentComponent);
                    componentIdentityBomRefs.put(persistentComponent.getBomRef(), newComponentIdentity);
                    persistentComponents.put(newComponentIdentity, persistentComponent);

                    // Note: persistentComponent does not need to be detached.
                    // The constructor of ComponentVulnerabilityAnalysisEvent merely calls a few getters on it,
                    // but the component object itself is not passed around. Detaching would imply additional
                    // database interactions that we'd rather not do.
                    vulnAnalysisEvents.add(new ComponentVulnerabilityAnalysisEvent(
                            event.getChainIdentifier(), persistentComponent, VulnerabilityAnalysisLevel.BOM_UPLOAD_ANALYSIS));

                    if (isNewOrUpdated) { // Flushing is only necessary when something changed
                        if (++numFlushableChanges >= flushThreshold) {
                            numFlushableChanges = 0;
                            pm.flush();
                        }
                    }
                }

                // Flush all remaining changes to the database.
                if (numFlushableChanges > 0) {
                    numFlushableChanges = 0;
                    pm.flush();
                }

                // License cache is no longer needed; Let go of it.
                LOGGER.info("Clearing " + licenseCache.size() + " entries from license cache for project: " + event.getProjectUuid()); // TODO: Remove
                licenseCache.clear();

                // Delete components that existed before this BOM import, but do not exist anymore.
                // TODO: Move into separate method
                if (!oldComponentIds.isEmpty()) {
                    LOGGER.info("Deleting " + oldComponentIds.size() + " old components from project: " + event.getProjectUuid()); // TODO: Remove
                    for (final Long componentId : oldComponentIds) {
                        final Query<Component> componentDeleteQuery = pm.newQuery(Component.class);
                        try {
                            componentDeleteQuery.setFilter("id == :id");
                            componentDeleteQuery.deletePersistentAll(componentId);
                        } finally {
                            componentDeleteQuery.closeAll();
                        }

                        if (++numFlushableChanges >= flushThreshold) {
                            numFlushableChanges = 0;
                            pm.flush();
                        }
                    }

                    // Flush all remaining changes to the database.
                    if (numFlushableChanges > 0) {
                        numFlushableChanges = 0;
                        pm.flush();
                    }
                }

                // Assemble dependency graph.
                // TODO: Move into separate method
                if (cdxBom.getMetadata() != null
                        && cdxBom.getMetadata().getComponent() != null
                        && cdxBom.getMetadata().getComponent().getBomRef() != null) {
                    final org.cyclonedx.model.Dependency metadataComponentDependency =
                            findDependencyByBomRef(cdxBom.getDependencies(), cdxBom.getMetadata().getComponent().getBomRef());

                    final var jsonDependencies = new JSONArray();
                    if (metadataComponentDependency != null && metadataComponentDependency.getDependencies() != null) {
                        for (final org.cyclonedx.model.Dependency dependency : metadataComponentDependency.getDependencies()) {
                            final ComponentIdentity dependencyIdentity = componentIdentityBomRefs.get(dependency.getRef());
                            if (dependencyIdentity != null) {
                                jsonDependencies.put(dependencyIdentity.toJSON());
                            } else {
                                LOGGER.warn("BOM ref " + dependency.getRef() + " does not match any component identity");
                            }
                        }
                    }
                    if (jsonDependencies.isEmpty()) {
                        project.setDirectDependencies(null);
                    } else {
                        project.setDirectDependencies(jsonDependencies.toString());
                    }
                }

                for (final Map.Entry<String, ComponentIdentity> entry : componentIdentityBomRefs.entrySet()) {
                    final ComponentIdentity identity = componentIdentityBomRefs.get(entry.getKey());
                    final org.cyclonedx.model.Dependency dependency = findDependencyByBomRef(cdxBom.getDependencies(), entry.getKey());

                    final var jsonDependencies = new JSONArray();
                    if (dependency != null && dependency.getDependencies() != null) {
                        for (final org.cyclonedx.model.Dependency dependency1 : dependency.getDependencies()) {
                            final ComponentIdentity dependencyIdentity = componentIdentityBomRefs.get(dependency1.getRef());
                            if (dependencyIdentity != null) {
                                jsonDependencies.put(dependencyIdentity.toJSON());
                            } else {
                                LOGGER.warn("BOM ref " + dependency.getRef() + " does not match any component identity");
                            }
                        }
                    }
                    final var jsonDependenciesStr = jsonDependencies.isEmpty() ? null : jsonDependencies.toString();

                    final Component persistentComponent = persistentComponents.get(identity);
                    if (persistentComponent != null) {
                        if (!Objects.equals(jsonDependenciesStr, persistentComponent.getDirectDependencies())) {
                            persistentComponent.setDirectDependencies(jsonDependenciesStr);

                            if (++numFlushableChanges >= flushThreshold) {
                                numFlushableChanges = 0;
                                pm.flush();
                            }
                        }
                    } else {
                        LOGGER.warn("""
                                Unable to resolve component identity %s to a persistent component; \
                                As a result, the dependency graph of project %s will likely be incomplete"""
                                .formatted(identity.toJSON(), event.getProjectUuid()));
                    }
                }

                // Flush all remaining changes to the database.
                if (numFlushableChanges > 0) {
                    numFlushableChanges = 0;
                    pm.flush();
                }

                LOGGER.info("Creating record for CycloneDX BOM upload to project: " + event.getProjectUuid());
                final var bom = new Bom();
                bom.setProject(project);
                bom.setBomFormat(Bom.Format.CYCLONEDX);
                bom.setSpecVersion(cdxBom.getSpecVersion());
                bom.setSerialNumber(cdxBom.getSerialNumber());
                bom.setBomVersion(cdxBom.getVersion());
                bom.setImported(new Date());
                pm.makePersistent(bom);

                project.setLastBomImport(bom.getImported());
                project.setLastBomImportFormat(bom.getBomFormat());

                trx.commit();
            } finally { // TODO: Catch exceptions and send BOM_PROCESSING_FAILED notification
                if (trx.isActive()) {
                    LOGGER.warn("Rolling back transaction for CycloneDX BOM upload to project: " + event.getProjectUuid()); // TODO: Remove
                    trx.rollback();
                }
            }

            if (!vulnAnalysisEvents.isEmpty()) {
                qm.createVulnerabilityScan(TargetType.PROJECT, event.getProjectUuid(), event.getChainIdentifier().toString(), vulnAnalysisEvents.size());
                for (final ComponentVulnerabilityAnalysisEvent vae : vulnAnalysisEvents) {
                    kafkaEventDispatcher.dispatchAsync(vae);
                    // kafkaEventDispatcher.dispatchAsync(new ComponentRepositoryMetaAnalysisEvent(component));
                }
            }

            // TODO: Submit components for repo meta analysis
            // TODO: Trigger index updates
            // TODO: Send BOM_PROCESSED notification
        }
    }

    private static org.cyclonedx.model.Dependency findDependencyByBomRef(final List<Dependency> dependencies, final String bomRef) {
        if (dependencies == null || dependencies.isEmpty() || bomRef == null) {
            return null;
        }

        for (final org.cyclonedx.model.Dependency dependency : dependencies) {
            if (bomRef.equals(dependency.getRef())) {
                return dependency;
            }
        }

        return null;
    }

    private org.cyclonedx.model.Bom parseBom(final BomUploadEvent event) throws IOException, ParseException {
        final byte[] bomBytes;
        try (final var bomFileInputStream = Files.newInputStream(event.getFile().toPath(), StandardOpenOption.DELETE_ON_CLOSE)) {
            bomBytes = bomFileInputStream.readAllBytes();
        }

        if (!BomParserFactory.looksLikeCycloneDX(bomBytes)) {
            throw new IllegalArgumentException("The BOM uploaded is not in a supported format. Supported formats include CycloneDX XML and JSON");
        }

        final Parser parser = BomParserFactory.createParser(bomBytes);
        return parser.parse(bomBytes);
    }

    private static <T> T executeUniqueQuery(final Query<T> query) {
        try {
            return query.executeUnique();
        } finally {
            query.closeAll();
        }
    }

    private static <T> List<T> executeResultListQuery(final Query<?> query, final Class<T> clazz) {
        try {
            return List.copyOf(query.executeResultList(clazz));
        } finally {
            query.closeAll();
        }
    }

    private static Predicate<Component> distinctComponentByIdentity(final Map<String, ComponentIdentity> componentIdentityBomRefs) {
        final var componentIdentitiesSeen = new HashSet<ComponentIdentity>();

        return component -> {
            final var componentIdentity = new ComponentIdentity(component);
            componentIdentityBomRefs.putIfAbsent(component.getBomRef(), componentIdentity);
            return componentIdentitiesSeen.add(componentIdentity);
        };
    }

    private static Predicate<ServiceComponent> distinctServiceByIdentity(final Map<String, ComponentIdentity> componentIdentityBomRefs) {
        final var componentIdentitiesSeen = new HashSet<ComponentIdentity>();

        return service -> {
            final var componentIdentity = new ComponentIdentity(service);
            componentIdentityBomRefs.putIfAbsent(service.getBomRef(), componentIdentity);
            return componentIdentitiesSeen.add(componentIdentity);
        };
    }

    /**
     * {@inheritDoc}
     */
    public void inform(final Event e) {
        if (e instanceof final BomUploadEvent event) {
            Project bomProcessingFailedProject = null;
            Bom.Format bomProcessingFailedBomFormat = null;
            String bomProcessingFailedBomVersion = null;
            final Timer.Sample timerSample = Timer.start();
            final QueryManager qm = new QueryManager().withL2CacheDisabled();
            try {
                final Project project = qm.getObjectByUuid(Project.class, event.getProjectUuid());
                if (project == null) {
                    LOGGER.warn("Ignoring BOM Upload event for no longer existing project " + event.getProjectUuid());
                    return;
                }
                bomProcessingFailedProject = project;
                final List<Component> components;
                final List<Component> newComponents = new ArrayList<>();
                final List<Component> flattenedComponents = new ArrayList<>();
                final List<ServiceComponent> services;
                final List<ServiceComponent> flattenedServices = new ArrayList<>();

                final byte[] bomBytes;
                try (final var bomFileInputStream = Files.newInputStream(event.getFile().toPath(), StandardOpenOption.DELETE_ON_CLOSE)) {
                    bomBytes = bomFileInputStream.readAllBytes();
                }

                // Holds a list of all Components that are existing dependencies of the specified project
                final List<Component> existingProjectComponents = qm.getAllComponents(project);
                final List<ServiceComponent> existingProjectServices = qm.getAllServiceComponents(project);
                final Bom.Format bomFormat;
                final String bomSpecVersion;
                final Integer bomVersion;
                final String serialNumnber;
                org.cyclonedx.model.Bom cycloneDxBom = null;
                if (BomParserFactory.looksLikeCycloneDX(bomBytes)) {
                    if (qm.isEnabled(ConfigPropertyConstants.ACCEPT_ARTIFACT_CYCLONEDX)) {
                        LOGGER.info("Processing CycloneDX BOM uploaded to project: " + event.getProjectUuid());
                        bomFormat = Bom.Format.CYCLONEDX;
                        bomProcessingFailedBomFormat = bomFormat;
                        final Parser parser = BomParserFactory.createParser(bomBytes);
                        cycloneDxBom = parser.parse(bomBytes);
                        bomSpecVersion = cycloneDxBom.getSpecVersion();
                        bomProcessingFailedBomVersion = bomSpecVersion;
                        bomVersion = cycloneDxBom.getVersion();
                        if (project.getClassifier() == null) {
                            final var classifier = Optional.ofNullable(cycloneDxBom.getMetadata())
                                    .map(org.cyclonedx.model.Metadata::getComponent)
                                    .map(org.cyclonedx.model.Component::getType)
                                    .map(org.cyclonedx.model.Component.Type::name)
                                    .map(Classifier::valueOf)
                                    .orElse(Classifier.APPLICATION);
                            project.setClassifier(classifier);
                        }
                        project.setExternalReferences(ModelConverter.convertBomMetadataExternalReferences(cycloneDxBom));
                        serialNumnber = (cycloneDxBom.getSerialNumber() != null) ? cycloneDxBom.getSerialNumber().replaceFirst("urn:uuid:", "") : null;
                        components = ModelConverter.convertComponents(qm, cycloneDxBom, project);
                        services = ModelConverter.convertServices(qm, cycloneDxBom, project);
                    } else {
                        LOGGER.warn("A CycloneDX BOM was uploaded but accepting CycloneDX BOMs is disabled. Aborting");
                        return;
                    }
                } else {
                    LOGGER.warn("The BOM uploaded is not in a supported format. Supported formats include CycloneDX XML and JSON");
                    return;
                }
                final Project copyOfProject = qm.detach(Project.class, qm.getObjectById(Project.class, project.getId()).getId());
                kafkaEventDispatcher.dispatchAsync(project.getUuid(),
                        new Notification()
                                .scope(NotificationScope.PORTFOLIO)
                                .group(NotificationGroup.BOM_CONSUMED)
                                .level(NotificationLevel.INFORMATIONAL)
                                .title(NotificationConstants.Title.BOM_CONSUMED)
                                .content("A " + bomFormat.getFormatShortName() + " BOM was consumed and will be processed")
                                .subject(new BomConsumedOrProcessed(copyOfProject, /* bom */ "(Omitted)", bomFormat, bomSpecVersion)));
                final Date date = new Date();
                final Bom bom = qm.createBom(project, date, bomFormat, bomSpecVersion, bomVersion, serialNumnber, event.getChainIdentifier());
                for (final Component component : components) {
                    processComponent(qm, component, flattenedComponents, newComponents);
                }
                LOGGER.info("Identified " + newComponents.size() + " new components");
                for (final ServiceComponent service : services) {
                    processService(qm, bom, service, flattenedServices);
                }
                if (Bom.Format.CYCLONEDX == bomFormat) {
                    LOGGER.info("Processing CycloneDX dependency graph for project: " + event.getProjectUuid());
                    ModelConverter.generateDependencies(cycloneDxBom, project, components);
                }
                LOGGER.debug("Reconciling components for project " + event.getProjectUuid());
                qm.reconcileComponents(project, existingProjectComponents, flattenedComponents);
                LOGGER.debug("Reconciling services for project " + event.getProjectUuid());
                qm.reconcileServiceComponents(project, existingProjectServices, flattenedServices);
                LOGGER.debug("Updating last import date for project " + event.getProjectUuid());
                qm.updateLastBomImport(project, date, bomFormat.getFormatShortName() + " " + bomSpecVersion);
                // Instead of firing off a new VulnerabilityAnalysisEvent, chain the VulnerabilityAnalysisEvent to
                // the BomUploadEvent so that synchronous publishing mode (Jenkins) waits until vulnerability
                // analysis has completed. If not chained, synchronous publishing mode will return immediately upon
                // return from this method, resulting in inaccurate findings being returned in the response (since
                // the vulnerability analysis hasn't taken place yet).
                final List<Component> detachedFlattenedComponents = qm.detach(flattenedComponents);
                final Project detachedProject = qm.detach(Project.class, project.getId());
                if (!detachedFlattenedComponents.isEmpty()) {
                    qm.createVulnerabilityScan(TargetType.PROJECT, project.getUuid(), event.getChainIdentifier().toString(), flattenedComponents.size());
                    for (final Component component : detachedFlattenedComponents) {
                        //check component belongs to list of new component
                        boolean isNewComponent = newComponents.stream().filter(component1 -> component1.getUuid().equals(component.getUuid())).findAny().isPresent();
                        kafkaEventDispatcher.dispatchAsync(new ComponentVulnerabilityAnalysisEvent(
                                event.getChainIdentifier(), component, VulnerabilityAnalysisLevel.BOM_UPLOAD_ANALYSIS, isNewComponent));
                        kafkaEventDispatcher.dispatchAsync(new ComponentRepositoryMetaAnalysisEvent(component));
                    }
                }
                LOGGER.info("Processed " + flattenedComponents.size() + " components and " + flattenedServices.size() + " services uploaded to project " + event.getProjectUuid());
                kafkaEventDispatcher.dispatchAsync(project.getUuid(), new Notification()
                        .scope(NotificationScope.PORTFOLIO)
                        .group(NotificationGroup.BOM_PROCESSED)
                        .level(NotificationLevel.INFORMATIONAL)
                        .title(NotificationConstants.Title.BOM_PROCESSED)
                        .content("A " + bomFormat.getFormatShortName() + " BOM was processed")
                        // FIXME: Add reference to BOM after we have dedicated BOM server
                        .subject(new BomConsumedOrProcessed(detachedProject, /* bom */ "(Omitted)", bomFormat, bomSpecVersion)));
            } catch (Exception ex) {
                LOGGER.error("Error while processing bom", ex);
                if (bomProcessingFailedProject != null) {
                    bomProcessingFailedProject = qm.detach(Project.class, bomProcessingFailedProject.getId());
                }
                kafkaEventDispatcher.dispatchAsync(bomProcessingFailedProject.getUuid(), new Notification()
                        .scope(NotificationScope.PORTFOLIO)
                        .group(NotificationGroup.BOM_PROCESSING_FAILED)
                        .title(NotificationConstants.Title.BOM_PROCESSING_FAILED)
                        .level(NotificationLevel.ERROR)
                        .content("An error occurred while processing a BOM")
                        // FIXME: Add reference to BOM after we have dedicated BOM server
                        .subject(new BomProcessingFailed(bomProcessingFailedProject, /* bom */ "(Omitted)", ex.getMessage(), bomProcessingFailedBomFormat, bomProcessingFailedBomVersion)));
            } finally {
                timerSample.stop(TIMER);
                qm.commitSearchIndex(true, Component.class);
                qm.commitSearchIndex(true, ServiceComponent.class);
                qm.close();
            }
        }
    }

    private void processComponent(final QueryManager qm, Component component,
                                  final List<Component> flattenedComponents,
                                  final List<Component> newComponents) {
        final boolean isNew = component.getUuid() == null;
        component.setInternal(isInternalComponent(component, qm));
        component = qm.createComponent(component, false);
        final long oid = component.getId();
        // Refreshing the object by querying for it again is preventative
        component = qm.getObjectById(Component.class, oid);
        flattenedComponents.add(component);
        if (isNew) {
            newComponents.add(qm.detach(Component.class, component.getId()));
        }
        if (component.getChildren() != null) {
            for (final Component child : component.getChildren()) {
                processComponent(qm, child, flattenedComponents, newComponents);
            }
        }
    }

    private void processService(final QueryManager qm, final Bom bom, ServiceComponent service,
                                final List<ServiceComponent> flattenedServices) {
        service = qm.createServiceComponent(service, false);
        final long oid = service.getId();
        // Refreshing the object by querying for it again is preventative
        flattenedServices.add(qm.getObjectById(ServiceComponent.class, oid));
        if (service.getChildren() != null) {
            for (final ServiceComponent child : service.getChildren()) {
                processService(qm, bom, child, flattenedServices);
            }
        }
    }
}
