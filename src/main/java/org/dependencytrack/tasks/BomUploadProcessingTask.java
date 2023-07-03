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
        final var componentIdentityBomRefs = new HashMap<String, ComponentIdentity>();
        final List<Component> components = flattenComponents(convertComponents(cdxBom.getComponents())).stream()
                .filter(distinctComponentByIdentity(componentIdentityBomRefs))
                .toList();
        LOGGER.info("Identified " + components.size() + " unique components in BOM uploaded to project: " + event.getProjectUuid()); // TODO: Remove

        final List<ServiceComponent> serviceComponents = flattenServices(convertServices(cdxBom.getServices())).stream()
                .filter(distinctServiceByIdentity(componentIdentityBomRefs))
                .toList();
        LOGGER.info("Identified " + serviceComponents.size() + " unique services in BOM uploaded to project: " + event.getProjectUuid()); // TODO: Remove

        // TODO: Send BOM_CONSUMED_NOTIFICATION

        try (final var qm = new QueryManager()) {
            final PersistenceManager pm = qm.getPersistenceManager();
            pm.setProperty(PropertyNames.PROPERTY_PERSISTENCE_BY_REACHABILITY_AT_COMMIT, "false");
            pm.setProperty(PropertyNames.PROPERTY_FLUSH_MODE, FlushMode.MANUAL.name());

            LOGGER.info("Processing CycloneDX BOM uploaded to project: " + event.getProjectUuid());

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
                // We'll use them later to determine which components to delete.
                final Query<Component> oldComponentIdsQuery = pm.newQuery(Component.class);
                oldComponentIdsQuery.setFilter("project == :project");
                oldComponentIdsQuery.setParameters(project);
                oldComponentIdsQuery.setResult("id");
                final Set<Long> oldComponentIds = new HashSet<>(executeResultListQuery(oldComponentIdsQuery, Long.class));

                // Avoid redundant queries by caching resolved licenses.
                final var licenseCache = new HashMap<String, License>();

                // Save some database round-trips by only flushing changes every "flushThreshold" components,
                // See https://www.datanucleus.org/products/accessplatform_4_1/jdo/performance_tuning.html
                final int flushThreshold = 10000;
                int numFlushableChanges = 0;

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

                    final boolean shouldFlush;
                    final var componentIdentity = new ComponentIdentity(component);
                    final Component existingComponent = qm.matchSingleIdentity(project, componentIdentity);
                    if (existingComponent == null) {
                        component.setProject(project);
                        pm.makePersistent(component);
                        shouldFlush = true;

                        // TODO: Mark as "new"
                    } else {
                        // Only call setters when values actually changed. Otherwise, we'll trigger lots of unnecessary
                        // database calls.
                        var changed = false;
                        changed |= applyIfChanged(existingComponent, component, Component::getAuthor, existingComponent::setAuthor);
                        changed |= applyIfChanged(existingComponent, component, Component::getPublisher, existingComponent::setPublisher);
                        changed |= applyIfChanged(existingComponent, component, Component::getBomRef, existingComponent::setBomRef);
                        changed |= applyIfChanged(existingComponent, component, Component::getClassifier, existingComponent::setClassifier);
                        changed |= applyIfChanged(existingComponent, component, Component::getGroup, existingComponent::setGroup);
                        changed |= applyIfChanged(existingComponent, component, Component::getName, existingComponent::setName);
                        changed |= applyIfChanged(existingComponent, component, Component::getVersion, existingComponent::setVersion);
                        changed |= applyIfChanged(existingComponent, component, Component::getDescription, existingComponent::setDescription);
                        changed |= applyIfChanged(existingComponent, component, Component::getCopyright, existingComponent::setCopyright);
                        changed |= applyIfChanged(existingComponent, component, Component::getCpe, existingComponent::setCpe);
                        changed |= applyIfChanged(existingComponent, component, Component::getPurl, existingComponent::setPurl);
                        changed |= applyIfChanged(existingComponent, component, Component::getSwidTagId, existingComponent::setSwidTagId);
                        changed |= applyIfChanged(existingComponent, component, Component::getMd5, existingComponent::setMd5);
                        changed |= applyIfChanged(existingComponent, component, Component::getSha1, existingComponent::setSha1);
                        changed |= applyIfChanged(existingComponent, component, Component::getSha256, existingComponent::setSha256);
                        changed |= applyIfChanged(existingComponent, component, Component::getSha384, existingComponent::setSha384);
                        changed |= applyIfChanged(existingComponent, component, Component::getSha512, existingComponent::setSha512);
                        changed |= applyIfChanged(existingComponent, component, Component::getSha3_256, existingComponent::setSha3_256);
                        changed |= applyIfChanged(existingComponent, component, Component::getSha3_384, existingComponent::setSha3_384);
                        changed |= applyIfChanged(existingComponent, component, Component::getSha3_512, existingComponent::setSha3_512);
                        changed |= applyIfChanged(existingComponent, component, Component::getBlake2b_256, existingComponent::setBlake2b_256);
                        changed |= applyIfChanged(existingComponent, component, Component::getBlake2b_384, existingComponent::setBlake2b_384);
                        changed |= applyIfChanged(existingComponent, component, Component::getBlake2b_512, existingComponent::setBlake2b_512);
                        changed |= applyIfChanged(existingComponent, component, Component::getBlake3, existingComponent::setBlake3);
                        changed |= applyIfChanged(existingComponent, component, Component::getResolvedLicense, existingComponent::setResolvedLicense);
                        changed |= applyIfChanged(existingComponent, component, Component::getLicense, existingComponent::setLicense);
                        changed |= applyIfChanged(existingComponent, component, Component::getLicenseUrl, existingComponent::setLicenseUrl);
                        changed |= applyIfChanged(existingComponent, component, Component::isInternal, existingComponent::setInternal);
                        shouldFlush = changed;

                        // Exclude from components to delete.
                        if (!oldComponentIds.isEmpty()) {
                            oldComponentIds.remove(existingComponent.getId());
                        }
                    }

                    if (shouldFlush) {
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
                    }
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

            // TODO: Submit components for vuln analysis
            // TODO: Submit components for repo meta analysis
            // TODO: Trigger index updates
            // TODO: Send BOM_PROCESSED notification
        }
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
