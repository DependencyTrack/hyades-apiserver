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
import org.cyclonedx.parsers.Parser;
import org.dependencytrack.event.BomUploadEvent;
import org.dependencytrack.event.ComponentRepositoryMetaAnalysisEvent;
import org.dependencytrack.event.ComponentVulnerabilityAnalysisEvent;
import org.dependencytrack.event.kafka.KafkaEventDispatcher;
import org.dependencytrack.model.Bom;
import org.dependencytrack.model.Classifier;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ConfigPropertyConstants;
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
import org.dependencytrack.util.InternalComponentIdentificationUtil;

import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Optional;

/**
 * Subscriber task that performs processing of bill-of-material (bom)
 * when it is uploaded.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public class BomUploadProcessingTask implements Subscriber {

    private static final Logger LOGGER = Logger.getLogger(BomUploadProcessingTask.class);
    private static final Timer TIMER = Timer.builder("bom_upload_processing")
            .description("Time taken to process / ingest uploaded Bill of Materials")
            .register(Metrics.getRegistry());

    private final KafkaEventDispatcher kafkaEventDispatcher;

    public BomUploadProcessingTask() {
        this(new KafkaEventDispatcher());
    }

    BomUploadProcessingTask(final KafkaEventDispatcher kafkaEventDispatcher) {
        this.kafkaEventDispatcher = kafkaEventDispatcher;
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
                        kafkaEventDispatcher.dispatchAsync(new ComponentVulnerabilityAnalysisEvent(
                                event.getChainIdentifier(), component, VulnerabilityAnalysisLevel.BOM_UPLOAD_ANALYSIS));
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
        component.setInternal(InternalComponentIdentificationUtil.isInternalComponent(component, qm));
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
