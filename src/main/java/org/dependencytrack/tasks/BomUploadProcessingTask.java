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
import org.apache.kafka.clients.producer.RecordMetadata;
import org.cyclonedx.BomParserFactory;
import org.cyclonedx.exception.ParseException;
import org.cyclonedx.model.Dependency;
import org.cyclonedx.parsers.Parser;
import org.datanucleus.flush.FlushMode;
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
import org.dependencytrack.persistence.FlushHelper;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.proto.repometaanalysis.v1.FetchMeta;
import org.json.JSONArray;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import javax.jdo.Transaction;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.function.Predicate;
import java.util.stream.Stream;

import static org.apache.commons.lang3.StringUtils.isNotBlank;
import static org.apache.commons.lang3.StringUtils.trim;
import static org.apache.commons.lang3.StringUtils.trimToNull;
import static org.datanucleus.PropertyNames.PROPERTY_FLUSH_MODE;
import static org.datanucleus.PropertyNames.PROPERTY_PERSISTENCE_BY_REACHABILITY_AT_COMMIT;
import static org.datanucleus.PropertyNames.PROPERTY_RETAIN_VALUES;
import static org.dependencytrack.common.ConfigKey.BOM_UPLOAD_PROCESSING_TRX_FLUSH_THRESHOLD;
import static org.dependencytrack.event.kafka.componentmeta.RepoMetaConstants.SUPPORTED_PACKAGE_URLS_FOR_INTEGRITY_CHECK;
import static org.dependencytrack.event.kafka.componentmeta.RepoMetaConstants.TIME_SPAN;
import static org.dependencytrack.parser.cyclonedx.util.ModelConverter.convertComponents;
import static org.dependencytrack.parser.cyclonedx.util.ModelConverter.convertServices;
import static org.dependencytrack.parser.cyclonedx.util.ModelConverter.convertToProject;
import static org.dependencytrack.parser.cyclonedx.util.ModelConverter.convertToProjectMetadata;
import static org.dependencytrack.parser.cyclonedx.util.ModelConverter.flatten;
import static org.dependencytrack.util.InternalComponentIdentificationUtil.isInternalComponent;
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

    private static final Logger LOGGER = Logger.getLogger(BomUploadProcessingTask.class);
    private static final int FLUSH_THRESHOLD = Config.getInstance().getPropertyAsInt(BOM_UPLOAD_PROCESSING_TRX_FLUSH_THRESHOLD);

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
        if (e instanceof final BomUploadEvent event) {
            final var ctx = new Context(event.getProject(), event.getChainIdentifier());
            try {
                processBom(ctx, event.getFile());
                LOGGER.info("BOM processed successfully (%s)".formatted(ctx));
                updateState(ctx, WorkflowStep.BOM_PROCESSING, WorkflowStatus.COMPLETED);
                if (!delayBomProcessedNotification) {
                    dispatchBomProcessedNotification(ctx);
                } else {
                    // The notification will be dispatched by the Kafka Streams topology,
                    // when it detects that the vulnerability scan completed.
                    LOGGER.warn("Not dispatching %s notification, because %s is enabled (%s)"
                            .formatted(NotificationGroup.BOM_PROCESSED, ConfigKey.TMP_DELAY_BOM_PROCESSED_NOTIFICATION.getPropertyName(), ctx));
                }
            } catch (BomConsumptionException ex) {
                LOGGER.error("BOM consumption failed (%s)".formatted(ex.ctx), ex);
                updateStateAndCancelDescendants(ctx, WorkflowStep.BOM_CONSUMPTION, WorkflowStatus.FAILED, ex.getMessage());
                kafkaEventDispatcher.dispatchNotification(new Notification()
                        .scope(NotificationScope.PORTFOLIO)
                        .group(NotificationGroup.BOM_PROCESSING_FAILED)
                        .level(NotificationLevel.ERROR)
                        .title(NotificationConstants.Title.BOM_PROCESSING_FAILED)
                        .content("An error occurred while processing a BOM")
                        // TODO: Look into adding more fields to BomProcessingFailed, to also cover upload token, serial number, version, etc.
                        // FIXME: Add reference to BOM after we have dedicated BOM server
                        .subject(new BomProcessingFailed(ctx.uploadToken, ctx.project, /* bom */ "(Omitted)", ex.getMessage(), ex.ctx.bomFormat, ex.ctx.bomSpecVersion)));
            } catch (BomProcessingException ex) {
                LOGGER.error("BOM processing failed (%s)".formatted(ex.ctx), ex);
                updateStateAndCancelDescendants(ctx, WorkflowStep.BOM_PROCESSING, WorkflowStatus.FAILED, ex.getMessage());
                kafkaEventDispatcher.dispatchNotification(new Notification()
                        .scope(NotificationScope.PORTFOLIO)
                        .group(NotificationGroup.BOM_PROCESSING_FAILED)
                        .level(NotificationLevel.ERROR)
                        .title(NotificationConstants.Title.BOM_PROCESSING_FAILED)
                        .content("An error occurred while processing a BOM")
                        // TODO: Look into adding more fields to BomProcessingFailed, to also cover upload token, serial number, version, etc.
                        //   Thanks to ctx we now have more information about the BOM that may be useful to consumers downstream.
                        // FIXME: Add reference to BOM after we have dedicated BOM server
                        .subject(new BomProcessingFailed(ctx.uploadToken, ctx.project, /* bom */ "(Omitted)", ex.getMessage(), ex.ctx.bomFormat, ex.ctx.bomSpecVersion)));
            } catch (Exception ex) {
                LOGGER.error("BOM processing failed unexpectedly (%s)".formatted(ctx), ex);
                updateStateAndCancelDescendants(ctx, WorkflowStep.BOM_PROCESSING, WorkflowStatus.FAILED, ex.getMessage());
                kafkaEventDispatcher.dispatchNotification(new Notification()
                        .scope(NotificationScope.PORTFOLIO)
                        .group(NotificationGroup.BOM_PROCESSING_FAILED)
                        .level(NotificationLevel.ERROR)
                        .title(NotificationConstants.Title.BOM_PROCESSING_FAILED)
                        .content("An error occurred while processing a BOM")
                        // FIXME: Add reference to BOM after we have dedicated BOM server
                        .subject(new BomProcessingFailed(ctx.uploadToken, ctx.project, /* bom */ "(Omitted)", ex.getMessage(), ctx.bomFormat /* (may be null) */, ctx.bomSpecVersion /* (may be null) */)));
            }
        }
    }

    private void processBom(final Context ctx, final File bomFile) throws BomConsumptionException, BomProcessingException {
        LOGGER.info("Consuming uploaded BOM (%s)".formatted(ctx));
        WorkflowState bomConsumptionState = null;
        try (final var qm = new QueryManager()) {
            WorkflowState consumptionState = qm.getWorkflowStateByTokenAndStep(ctx.uploadToken, WorkflowStep.BOM_CONSUMPTION);
            if (consumptionState != null) {
                consumptionState.setStartedAt(Date.from(Instant.now()));
                bomConsumptionState = qm.persist(consumptionState);
            } else {
                //TODO change the log level to error and throw exception once the workflow has been migrated completely
                LOGGER.warn("Workflow state for BOM_CONSUMPTION not found in database so cannot be updated for context: (%s)".formatted(ctx));
            }
        }
        final org.cyclonedx.model.Bom cdxBom = parseBom(ctx, bomFile);

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
        components = components.stream()
                .filter(distinctComponentsByIdentity(identitiesByBomRef, bomRefsByIdentity))
                .toList();
        List<ServiceComponent> services = convertServices(cdxBom.getServices());
        services = flatten(services, ServiceComponent::getChildren, ServiceComponent::setChildren);
        final int numServicesTotal = services.size();
        services = services.stream()
                .filter(distinctServicesByIdentity(identitiesByBomRef, bomRefsByIdentity))
                .toList();

        LOGGER.info("Consumed %d components (%d before de-duplication) and %d services (%d before de-duplication) from uploaded BOM (%s)"
                .formatted(components.size(), numComponentsTotal, services.size(), numServicesTotal, ctx));

        //complete the Bom consumption state and start the processing state
        if (bomConsumptionState != null) {
            try (var qm = new QueryManager()) {
                bomConsumptionState.setStatus(WorkflowStatus.COMPLETED);
                bomConsumptionState.setUpdatedAt(Date.from(Instant.now()));
                qm.updateWorkflowState(bomConsumptionState);

                WorkflowState processingState = qm.getWorkflowStateByTokenAndStep(ctx.uploadToken, WorkflowStep.BOM_PROCESSING);
                processingState.setStartedAt(Date.from(Instant.now()));
                qm.persist(processingState);
            }
        }

        kafkaEventDispatcher.dispatchNotification(new Notification()
                .scope(NotificationScope.PORTFOLIO)
                .group(NotificationGroup.BOM_CONSUMED)
                .level(NotificationLevel.INFORMATIONAL)
                .title(NotificationConstants.Title.BOM_CONSUMED)
                .content("A %s BOM was consumed and will be processed".formatted(ctx.bomFormat.getFormatShortName()))
                .subject(new BomConsumedOrProcessed(ctx.uploadToken, ctx.project, /* bom */ "(Omitted)", ctx.bomFormat, ctx.bomSpecVersion)));


        final var vulnAnalysisEvents = new ArrayList<ComponentVulnerabilityAnalysisEvent>();
        final var repoMetaAnalysisEvents = new ArrayList<ComponentRepositoryMetaAnalysisEvent>();

        try (final var qm = new QueryManager()) {
            final PersistenceManager pm = qm.getPersistenceManager();

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
            pm.setProperty(PROPERTY_PERSISTENCE_BY_REACHABILITY_AT_COMMIT, "false");

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
            pm.setProperty(PROPERTY_FLUSH_MODE, FlushMode.MANUAL.name());

            // Prevent object fields from being unloaded upon commit.
            //
            // DataNucleus transitions objects into the "hollow" state after the transaction is committed.
            // In hollow state, all fields except the ID are unloaded. Accessing fields afterward triggers
            // one or more database queries to load them again.
            // See https://www.datanucleus.org/products/accessplatform_6_0/jdo/persistence.html#lifecycle
            qm.getPersistenceManager().setProperty(PROPERTY_RETAIN_VALUES, "true");

            LOGGER.info("Processing %d components and %d services from BOM (%s)"
                    .formatted(components.size(), services.size(), ctx));

            final Transaction trx = pm.currentTransaction();
            try {
                trx.begin();
                final Project persistentProject = processProject(ctx, pm, project, projectMetadata);
                final Map<ComponentIdentity, Component> persistentComponents =
                        processComponents(qm, persistentProject, components, identitiesByBomRef, bomRefsByIdentity);
                final Map<ComponentIdentity, ServiceComponent> persistentServices =
                        processServices(qm, persistentProject, services, identitiesByBomRef, bomRefsByIdentity);
                processDependencyGraph(ctx, pm, cdxBom, persistentProject, persistentComponents, persistentServices, identitiesByBomRef);
                Date bomGeneratedTimestamp = null;
                if (cdxBom.getMetadata() != null && cdxBom.getMetadata().getTimestamp() != null) {
                    bomGeneratedTimestamp = cdxBom.getMetadata().getTimestamp();
                }
                recordBomImport(ctx, pm, persistentProject, bomGeneratedTimestamp);
                // BOM ref <-> ComponentIdentity indexes are no longer needed.
                // Let go of their contents to make it eligible for GC sooner.
                identitiesByBomRef.clear();
                bomRefsByIdentity.clear();

                for (final Component component : persistentComponents.values()) {
                    // Note: component does not need to be detached.
                    // The constructors of ComponentRepositoryMetaAnalysisEvent and ComponentVulnerabilityAnalysisEvent
                    // merely call a few getters on it, but the component object itself is not passed around.
                    // Detaching would imply additional database interactions that we'd rather not do.
                    if (component.getPurl() != null) {
                        if (SUPPORTED_PACKAGE_URLS_FOR_INTEGRITY_CHECK.contains(component.getPurl().getType())) {
                            repoMetaAnalysisEvents.add(new ComponentRepositoryMetaAnalysisEvent(component.getUuid(),
                                    component.getPurl().canonicalize(), component.isInternal(), FetchMeta.FETCH_META_INTEGRITY_DATA_AND_LATEST_VERSION));
                        } else {
                            repoMetaAnalysisEvents.add(new ComponentRepositoryMetaAnalysisEvent(component.getUuid(),
                                    component.getPurlCoordinates().toString(), component.isInternal(), FetchMeta.FETCH_META_LATEST_VERSION));
                        }
                    }
                    vulnAnalysisEvents.add(new ComponentVulnerabilityAnalysisEvent(
                            ctx.uploadToken, component, VulnerabilityAnalysisLevel.BOM_UPLOAD_ANALYSIS, component.isNew()));
                }

                trx.commit();
            } finally {
                if (trx.isActive()) {
                    trx.rollback();
                }
            }

            // Clear the PersistenceManager's L1 cache.
            // Lessens some overhead of DataNucleus-internal housekeeping during
            // the following persistence operations.
            pm.evictAll();

            final var dispatchedEvents = new ArrayList<CompletableFuture<?>>();
            final var vulnAnalysisState = qm.getWorkflowStateByTokenAndStep(ctx.uploadToken, WorkflowStep.VULN_ANALYSIS);
            if (!vulnAnalysisEvents.isEmpty()) {
                qm.createVulnerabilityScan(TargetType.PROJECT, ctx.project.getUuid(), ctx.uploadToken.toString(), vulnAnalysisEvents.size());
                // Initiate vuln-analysis workflow for the token
                if (vulnAnalysisState != null) {
                    vulnAnalysisState.setStartedAt(Date.from(Instant.now()));
                    qm.persist(vulnAnalysisState);
                }

                for (final ComponentVulnerabilityAnalysisEvent event : vulnAnalysisEvents) {
                    final CompletableFuture<RecordMetadata> future = kafkaEventDispatcher.dispatchEvent(event)
                            .whenComplete((ignored, throwable) -> {
                                if (throwable != null) {
                                    // Include context in the log message to make log correlation easier.
                                    LOGGER.error("Failed to produce %s to Kafka (%s)".formatted(event, ctx), throwable);
                                }
                            });
                    dispatchedEvents.add(future);
                }
            } else {
                // No components to be sent for vulnerability analysis.
                // If the BOM_PROCESSED notification was delayed, dispatch it now.
                if (delayBomProcessedNotification) {
                    dispatchBomProcessedNotification(ctx);
                }

                if (vulnAnalysisState != null) {
                    vulnAnalysisState.setStatus(WorkflowStatus.NOT_APPLICABLE);
                    vulnAnalysisState.setUpdatedAt(Date.from(Instant.now()));
                    qm.updateWorkflowState(vulnAnalysisState);
                    // make only policy evaluation state NA
                    var policyEvaluationState = qm.getWorkflowStateByTokenAndStep(ctx.uploadToken, WorkflowStep.POLICY_EVALUATION);
                    policyEvaluationState.setStatus(WorkflowStatus.NOT_APPLICABLE);
                    policyEvaluationState.setUpdatedAt(Date.from(Instant.now()));
                    qm.updateWorkflowState(policyEvaluationState);
                    // Trigger project metrics update no matter if vuln analysis is applicable or not
                    final ChainableEvent metricsUpdateEvent = new ProjectMetricsUpdateEvent(ctx.project.getUuid());
                    metricsUpdateEvent.setChainIdentifier(ctx.uploadToken);
                    Event.dispatch(metricsUpdateEvent);
                }
            }

            for (final ComponentRepositoryMetaAnalysisEvent event : repoMetaAnalysisEvents) {
                final ComponentRepositoryMetaAnalysisEvent eventToSend;
                if (event.fetchMeta() == FetchMeta.FETCH_META_INTEGRITY_DATA_AND_LATEST_VERSION) {
                    final boolean shouldFetchIntegrityData = qm.runInTransaction(() -> prepareIntegrityMetaComponent(event, qm));
                    if (shouldFetchIntegrityData) {
                        eventToSend = event;
                    } else {
                        // If integrity metadata was fetched recently, we don't want to fetch it again
                        // as it's unlikely to change frequently. Fall back to fetching only the latest
                        // version information.
                        eventToSend = new ComponentRepositoryMetaAnalysisEvent(null, event.purlCoordinates(),
                                event.internal(), FetchMeta.FETCH_META_LATEST_VERSION);
                    }
                } else {
                    eventToSend = event;
                }

                final CompletableFuture<RecordMetadata> future = kafkaEventDispatcher.dispatchEvent(eventToSend)
                        .whenComplete((ignored, throwable) -> {
                            if (throwable != null) {
                                // Include context in the log message to make log correlation easier.
                                LOGGER.error("Failed to produce %s to Kafka (%s)".formatted(eventToSend, ctx), throwable);
                            }
                        });
                dispatchedEvents.add(future);
            }

            // Before proceeding, wait for all events to be delivered successfully.
            CompletableFuture.allOf(dispatchedEvents.toArray(new CompletableFuture[0])).join();
        }
    }

    private static void updateStateAndCancelDescendants(final Context ctx, WorkflowStep transientStep, WorkflowStatus transientStatus, String failureReason) {
        try (var qm = new QueryManager()) {
            WorkflowState workflowState = qm.getWorkflowStateByTokenAndStep(ctx.uploadToken, transientStep);
            if (workflowState != null) {
                workflowState.setStatus(transientStatus);
                workflowState.setFailureReason(failureReason);
                workflowState.setUpdatedAt(Date.from(Instant.now()));
                WorkflowState updatedState = qm.updateWorkflowState(workflowState);
                qm.updateAllDescendantStatesOfParent(updatedState, WorkflowStatus.CANCELLED, Date.from(Instant.now()));
            }
        }
    }

    private static void updateState(final Context ctx, WorkflowStep transientStep, WorkflowStatus transientStatus) {
        try (var qm = new QueryManager()) {
            WorkflowState workflowState = qm.getWorkflowStateByTokenAndStep(ctx.uploadToken, transientStep);
            if (workflowState != null) {
                workflowState.setStatus(transientStatus);
                workflowState.setUpdatedAt(Date.from(Instant.now()));
                qm.updateWorkflowState(workflowState);
            }
        }
    }


    private static org.cyclonedx.model.Bom parseBom(final Context ctx, final File bomFile) throws BomConsumptionException {
        final byte[] bomBytes;
        try (final var bomFileInputStream = Files.newInputStream(bomFile.toPath(), StandardOpenOption.DELETE_ON_CLOSE)) {
            bomBytes = bomFileInputStream.readAllBytes();
        } catch (IOException e) {
            throw new BomConsumptionException(ctx, "Failed to read BOM file", e);
        }

        // The file is verified to contain valid CycloneDX upon upload.
        ctx.bomFormat = Bom.Format.CYCLONEDX;

        final org.cyclonedx.model.Bom bom;
        try {
            final Parser parser = BomParserFactory.createParser(bomBytes);
            bom = parser.parse(bomBytes);
        } catch (ParseException e) {
            throw new BomConsumptionException(ctx, "Failed to parse BOM", e);
        }

        ctx.bomSpecVersion = bom.getSpecVersion();
        if (bom.getSerialNumber() != null) {
            ctx.bomSerialNumber = bom.getSerialNumber().replaceFirst("urn:uuid:", "");
        }
        ctx.bomVersion = bom.getVersion();


        return bom;
    }

    private static Project processProject(final Context ctx, final PersistenceManager pm,
                                          final Project project, final ProjectMetadata projectMetadata) throws BomProcessingException {
        final Query<Project> query = pm.newQuery(Project.class);
        query.setFilter("uuid == :uuid");
        query.setParameters(ctx.project.getUuid());

        final Project persistentProject;
        try {
            persistentProject = query.executeUnique();
        } finally {
            query.closeAll();
        }
        if (persistentProject == null) {
            throw new BomProcessingException(ctx, "Project does not exist");
        }

        boolean hasChanged = false;
        if (project != null) {
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
                pm.makePersistent(projectMetadata);
                hasChanged = true;
            } else {
                hasChanged |= applyIfChanged(persistentProject.getMetadata(), projectMetadata, ProjectMetadata::getAuthors,
                        authors -> persistentProject.getMetadata().setAuthors(authors != null ? new ArrayList<>(authors) : null));
                hasChanged |= applyIfChanged(persistentProject.getMetadata(), projectMetadata, ProjectMetadata::getSupplier, persistentProject.getMetadata()::setSupplier);
                hasChanged |= applyIfChanged(persistentProject.getMetadata(), projectMetadata, ProjectMetadata::getTools, persistentProject.getMetadata()::setTools);
            }
        }

        if (hasChanged) {
            pm.flush();
        }

        return persistentProject;
    }

    private static Map<ComponentIdentity, Component> processComponents(final QueryManager qm,
                                                                       final Project project,
                                                                       final List<Component> components,
                                                                       final Map<String, ComponentIdentity> identitiesByBomRef,
                                                                       final MultiValuedMap<ComponentIdentity, String> bomRefsByIdentity) {
        assertPersistent(project, "Project must be persistent");

        final PersistenceManager pm = qm.getPersistenceManager();

        // Fetch IDs of all components that exist in the project already.
        // We'll need them later to determine which components to delete.
        final Set<Long> oldComponentIds = getAllComponentIds(pm, project, Component.class);

        // Avoid redundant queries by caching resolved licenses.
        // It is likely that if license IDs were present in a BOM,
        // they appear multiple times for different components.
        final var licenseCache = new HashMap<String, License>();

        // We support resolution of custom licenses by their name.
        // To avoid any conflicts with license IDs, cache those separately.
        final var customLicenseCache = new HashMap<String, License>();

        final var persistentComponents = new HashMap<ComponentIdentity, Component>();
        try (final var flushHelper = new FlushHelper(qm, FLUSH_THRESHOLD)) {
            for (final Component component : components) {
                component.setInternal(isInternalComponent(component, qm));

                // CycloneDX components can declare multiple licenses, but we currently
                // only support one. We assume that the licenseCandidates list is ordered
                // by priority, and simply take the first resolvable candidate.
                for (final org.cyclonedx.model.License licenseCandidate : component.getLicenseCandidates()) {
                    if (isNotBlank(licenseCandidate.getId())) {
                        final License resolvedLicense = resolveLicense(pm, licenseCache, licenseCandidate.getId());
                        if (resolvedLicense != null) {
                            component.setResolvedLicense(resolvedLicense);
                            component.setLicenseUrl(trimToNull(licenseCandidate.getUrl()));
                            break;
                        }
                    }

                    if (isNotBlank(licenseCandidate.getName())) {
                        final License resolvedCustomLicense = resolveCustomLicense(pm, customLicenseCache, licenseCandidate.getName());
                        if (resolvedCustomLicense != null) {
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

                final boolean isNewOrUpdated;
                final var componentIdentity = new ComponentIdentity(component);
                Component persistentComponent = qm.matchSingleIdentity(project, componentIdentity);
                if (persistentComponent == null) {
                    component.setProject(project);
                    persistentComponent = pm.makePersistent(component);
                    persistentComponent.setNew(true); // transient
                    isNewOrUpdated = true;
                } else {
                    var changed = false;
                    changed |= applyIfChanged(persistentComponent, component, Component::getAuthor, persistentComponent::setAuthor);
                    changed |= applyIfChanged(persistentComponent, component, Component::getPublisher, persistentComponent::setPublisher);
                    changed |= applyIfChanged(persistentComponent, component, Component::getSupplier, persistentComponent::setSupplier);
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
                    changed |= applyIfChanged(persistentComponent, component, Component::getExternalReferences, persistentComponent::setExternalReferences);
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
                // Applications like the frontend rely on UUIDs being there.
                final var newIdentity = new ComponentIdentity(persistentComponent);
                final ComponentIdentity oldIdentity = identitiesByBomRef.put(persistentComponent.getBomRef(), newIdentity);
                for (final String bomRef : bomRefsByIdentity.get(oldIdentity)) {
                    identitiesByBomRef.put(bomRef, newIdentity);
                }
                persistentComponents.put(newIdentity, persistentComponent);

                if (isNewOrUpdated) { // Flushing is only necessary when something changed
                    flushHelper.maybeFlush();
                }
            }
        }

        // License cache is no longer needed; Let go of it.
        licenseCache.clear();
        customLicenseCache.clear();

        // Delete components that existed before this BOM import, but do not exist anymore.
        deleteComponentsById(pm, oldComponentIds);

        return persistentComponents;
    }

    private static Map<ComponentIdentity, ServiceComponent> processServices(final QueryManager qm,
                                                                            final Project project,
                                                                            final List<ServiceComponent> services,
                                                                            final Map<String, ComponentIdentity> identitiesByBomRef,
                                                                            final MultiValuedMap<ComponentIdentity, String> bomRefsByIdentity) {
        assertPersistent(project, "Project must be persistent");

        final PersistenceManager pm = qm.getPersistenceManager();

        // Fetch IDs of all services that exist in the project already.
        // We'll need them later to determine which services to delete.
        final Set<Long> oldServiceIds = getAllComponentIds(pm, project, ServiceComponent.class);

        final var persistentServices = new HashMap<ComponentIdentity, ServiceComponent>();

        try (final var flushHelper = new FlushHelper(qm, FLUSH_THRESHOLD)) {
            for (final ServiceComponent service : services) {
                final boolean isNewOrUpdated;
                final var componentIdentity = new ComponentIdentity(service);
                ServiceComponent persistentService = qm.matchServiceIdentity(project, componentIdentity);
                if (persistentService == null) {
                    service.setProject(project);
                    persistentService = pm.makePersistent(service);
                    isNewOrUpdated = true;
                } else {
                    var changed = false;
                    changed |= applyIfChanged(persistentService, service, ServiceComponent::getGroup, persistentService::setGroup);
                    changed |= applyIfChanged(persistentService, service, ServiceComponent::getName, persistentService::setName);
                    changed |= applyIfChanged(persistentService, service, ServiceComponent::getVersion, persistentService::setVersion);
                    changed |= applyIfChanged(persistentService, service, ServiceComponent::getDescription, persistentService::setDescription);
                    changed |= applyIfChanged(persistentService, service, ServiceComponent::getAuthenticated, persistentService::setAuthenticated);
                    changed |= applyIfChanged(persistentService, service, ServiceComponent::getCrossesTrustBoundary, persistentService::setCrossesTrustBoundary);
                    changed |= applyIfChanged(persistentService, service, ServiceComponent::getExternalReferences, persistentService::setExternalReferences);
                    changed |= applyIfChanged(persistentService, service, ServiceComponent::getProvider, persistentService::setProvider);
                    changed |= applyIfChanged(persistentService, service, ServiceComponent::getData, persistentService::setData);
                    changed |= applyIfChanged(persistentService, service, ServiceComponent::getEndpoints, persistentService::setEndpoints);
                    isNewOrUpdated = changed;

                    // BOM ref is transient and thus doesn't count towards the changed status.
                    persistentService.setBomRef(service.getBomRef());

                    // Exclude from components to delete.
                    if (!oldServiceIds.isEmpty()) {
                        oldServiceIds.remove(persistentService.getId());
                    }
                }

                // Update component identities in our Identity->BOMRef map,
                // as after persisting the services, their identities now include UUIDs.
                // Applications like the frontend rely on UUIDs being there.
                final var newIdentity = new ComponentIdentity(persistentService);
                final ComponentIdentity oldIdentity = identitiesByBomRef.put(service.getBomRef(), newIdentity);
                for (final String bomRef : bomRefsByIdentity.get(oldIdentity)) {
                    identitiesByBomRef.put(bomRef, newIdentity);
                }
                persistentServices.put(newIdentity, persistentService);

                if (isNewOrUpdated) { // Flushing is only necessary when something changed
                    flushHelper.maybeFlush();
                }
            }
        }

        // Delete components that existed before this BOM import, but do not exist anymore.
        deleteServicesById(pm, oldServiceIds);

        return persistentServices;
    }

    private static void processDependencyGraph(final Context ctx, final PersistenceManager pm, final org.cyclonedx.model.Bom cdxBom,
                                               final Project project, final Map<ComponentIdentity, Component> componentsByIdentity,
                                               @SuppressWarnings("unused") final Map<ComponentIdentity, ServiceComponent> servicesByIdentity,
                                               final Map<String, ComponentIdentity> identitiesByBomRef) {
        assertPersistent(project, "Project must be persistent");

        if (cdxBom.getMetadata() != null
                && cdxBom.getMetadata().getComponent() != null
                && cdxBom.getMetadata().getComponent().getBomRef() != null) {
            final org.cyclonedx.model.Dependency dependency =
                    findDependencyByBomRef(cdxBom.getDependencies(), cdxBom.getMetadata().getComponent().getBomRef());
            final String directDependenciesJson = resolveDirectDependenciesJson(ctx, dependency, identitiesByBomRef);
            if (!Objects.equals(directDependenciesJson, project.getDirectDependencies())) {
                project.setDirectDependencies(directDependenciesJson);
                pm.flush();
            }
        } else {
            // Make sure we don't retain stale data from previous BOM uploads.
            if (project.getDirectDependencies() != null) {
                project.setDirectDependencies(null);
                pm.flush();
            }
        }

        try (final var flushHelper = new FlushHelper(pm, FLUSH_THRESHOLD)) {
            for (final Map.Entry<String, ComponentIdentity> entry : identitiesByBomRef.entrySet()) {
                final org.cyclonedx.model.Dependency dependency = findDependencyByBomRef(cdxBom.getDependencies(), entry.getKey());
                final String directDependenciesJson = resolveDirectDependenciesJson(ctx, dependency, identitiesByBomRef);

                final ComponentIdentity dependencyIdentity = identitiesByBomRef.get(entry.getKey());
                final Component component = componentsByIdentity.get(dependencyIdentity);
                // TODO: Check servicesByIdentity when persistentComponent is null
                //   We do not currently store directDependencies for ServiceComponent
                if (component != null) {
                    assertPersistent(component, "Component must be persistent");
                    if (!Objects.equals(directDependenciesJson, component.getDirectDependencies())) {
                        component.setDirectDependencies(directDependenciesJson);
                        flushHelper.maybeFlush();
                    }
                } else {
                    LOGGER.warn("""
                            Unable to resolve component identity %s to a persistent component; \
                            As a result, the dependency graph of project %s will likely be incomplete (%s)"""
                            .formatted(dependencyIdentity.toJSON(), ctx.project.getUuid(), ctx));
                }
            }
        }
    }

    private static void recordBomImport(final Context ctx, final PersistenceManager pm, final Project project, Date bomGeneratedTimestamp) {
        assertPersistent(project, "Project must be persistent");

        final var bomImportDate = new Date();

        final var bom = new Bom();
        bom.setProject(project);
        bom.setBomFormat(ctx.bomFormat);
        bom.setSpecVersion(ctx.bomSpecVersion);
        bom.setSerialNumber(ctx.bomSerialNumber);
        bom.setBomVersion(ctx.bomVersion);
        bom.setImported(bomImportDate);
        bom.setGenerated(bomGeneratedTimestamp);
        pm.makePersistent(bom);

        project.setLastBomImport(bomImportDate);
        project.setLastBomImportFormat("%s %s".formatted(ctx.bomFormat.getFormatShortName(), ctx.bomSpecVersion));
    }

    private static String resolveDirectDependenciesJson(final Context ctx,
                                                        final org.cyclonedx.model.Dependency dependency,
                                                        final Map<String, ComponentIdentity> identitiesByBomRef) {
        final var jsonDependencies = new JSONArray();

        if (dependency != null && dependency.getDependencies() != null) {
            for (final org.cyclonedx.model.Dependency subDependency : dependency.getDependencies()) {
                final ComponentIdentity subDependencyIdentity = identitiesByBomRef.get(subDependency.getRef());
                if (subDependencyIdentity != null) {
                    jsonDependencies.put(subDependencyIdentity.toJSON());
                } else {
                    LOGGER.warn("""
                            Unable to resolve BOM ref %s to a component identity; \
                            As a result, the dependency graph of project %s will likely be incomplete (%s)"""
                            .formatted(dependency.getRef(), ctx.project.getUuid(), ctx));
                }
            }
        }

        return jsonDependencies.isEmpty() ? null : jsonDependencies.toString();
    }

    /**
     * Re-implementation of {@link QueryManager#recursivelyDelete(Component, boolean)} that does not use multiple
     * small {@link Transaction}s, but relies on an already active one instead. Instead of committing, it uses
     * {@link FlushHelper} to flush changes every {@link #FLUSH_THRESHOLD} write operations.
     * <p>
     * TODO: Move to {@link QueryManager}; Implement for {@link Project}s as well.
     *   When working on <a href="https://github.com/DependencyTrack/hyades/issues/636">#636</a>.
     *
     * @param pm           The {@link PersistenceManager} to use
     * @param componentIds IDs of {@link Component}s to delete
     */
    private static void deleteComponentsById(final PersistenceManager pm, final Set<Long> componentIds) {
        if (componentIds.isEmpty()) {
            return;
        }

        try (final var flushHelper = new FlushHelper(pm, FLUSH_THRESHOLD)) {
            for (final Long componentId : componentIds) {
                // Note: Bulk DELETE queries are executed directly in the database and do not need to be flushed.
                pm.newQuery(Query.JDOQL, "DELETE FROM org.dependencytrack.model.AnalysisComment WHERE analysis.component.id == :cid").execute(componentId);
                pm.newQuery(Query.JDOQL, "DELETE FROM org.dependencytrack.model.Analysis WHERE component.id == :cid").execute(componentId);
                pm.newQuery(Query.JDOQL, "DELETE FROM org.dependencytrack.model.ViolationAnalysisComment WHERE violationAnalysis.component.id == :cid").execute(componentId);
                pm.newQuery(Query.JDOQL, "DELETE FROM org.dependencytrack.model.ViolationAnalysis WHERE component.id == :cid").execute(componentId);
                pm.newQuery(Query.JDOQL, "DELETE FROM org.dependencytrack.model.DependencyMetrics WHERE component.id == :cid").execute(componentId);
                pm.newQuery(Query.JDOQL, "DELETE FROM org.dependencytrack.model.FindingAttribution WHERE component.id == :cid").execute(componentId);
                pm.newQuery(Query.JDOQL, "DELETE FROM org.dependencytrack.model.PolicyViolation WHERE component.id == :cid").execute(componentId);
                pm.newQuery(Query.JDOQL, "DELETE FROM org.dependencytrack.model.IntegrityAnalysis WHERE component.id == :cid").execute(componentId);

                // Can't use bulk DELETE for the component itself, as it doesn't remove entries from
                // relationship tables like COMPONENTS_VULNERABILITIES. deletePersistentAll does, but
                // it will also fetch the component prior to deleting it, which is slightly inefficient.
                pm.newQuery(Component.class, "id == :cid").deletePersistentAll(componentId);
                flushHelper.maybeFlush();
            }
        }
    }

    /**
     * Re-implementation of {@link QueryManager#recursivelyDelete(ServiceComponent, boolean)} that does not use multiple
     * small {@link Transaction}s, but relies on an already active one instead. Instead of committing, it uses
     * {@link FlushHelper} to flush changes every {@link #FLUSH_THRESHOLD} write operations.
     *
     * @param pm         The {@link PersistenceManager} to use
     * @param serviceIds IDs of {@link ServiceComponent}s to delete
     */
    private static void deleteServicesById(final PersistenceManager pm, final Set<Long> serviceIds) {
        if (serviceIds.isEmpty()) {
            return;
        }

        try (final var flushHelper = new FlushHelper(pm, FLUSH_THRESHOLD)) {
            for (final Long serviceId : serviceIds) {
                // Can't use bulk DELETE for the component itself, as it doesn't remove entries from
                // relationship tables like COMPONENTS_VULNERABILITIES. deletePersistentAll does, but
                // it will also fetch the component prior to deleting it, which is slightly inefficient.
                pm.newQuery(ServiceComponent.class, "id == :cid").deletePersistentAll(serviceId);
                flushHelper.maybeFlush();
            }
        }
    }

    /**
     * Lookup a {@link License} by its ID, and cache the result in {@code cache}.
     *
     * @param pm        The {@link PersistenceManager} to use
     * @param cache     A {@link Map} to use for caching
     * @param licenseId The {@link License} ID to lookup
     * @return The resolved {@link License}, or {@code null} if no {@link License} was found
     */
    private static License resolveLicense(final PersistenceManager pm, final Map<String, License> cache, final String licenseId) {
        if (cache.containsKey(licenseId)) {
            return cache.get(licenseId);
        }

        final Query<License> query = pm.newQuery(License.class);
        query.setFilter("licenseId == :licenseId");
        query.setParameters(licenseId);
        final License license;
        try {
            license = query.executeUnique();
        } finally {
            query.closeAll();
        }

        cache.put(licenseId, license);
        return license;
    }

    /**
     * Lookup a custom {@link License} by its name, and cache the result in {@code cache}.
     *
     * @param pm          The {@link PersistenceManager} to use
     * @param cache       A {@link Map} to use for caching
     * @param licenseName The {@link License} name to lookup
     * @return The resolved {@link License}, or {@code null} if no {@link License} was found
     */
    private static License resolveCustomLicense(final PersistenceManager pm, final Map<String, License> cache, final String licenseName) {
        if (cache.containsKey(licenseName)) {
            return cache.get(licenseName);
        }

        final Query<License> query = pm.newQuery(License.class);
        query.setFilter("name == :name && customLicense == true");
        query.setParameters(licenseName);
        final License license;
        try {
            license = query.executeUnique();
        } finally {
            query.closeAll();
        }

        cache.put(licenseName, license);
        return license;
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

    private static <T> Set<Long> getAllComponentIds(final PersistenceManager pm, final Project project, final Class<T> clazz) {
        final Query<T> query = pm.newQuery(clazz);
        query.setFilter("project == :project");
        query.setParameters(project);
        query.setResult("id");

        try {
            return new HashSet<>(query.executeResultList(Long.class));
        } finally {
            query.closeAll();
        }
    }

    /**
     * Factory for a stateful {@link Predicate} for de-duplicating {@link Component}s based on their {@link ComponentIdentity}.
     * <p>
     * The predicate will populate {@code identitiesByBomRef} and {@code bomRefsByIdentity}.
     *
     * @param identitiesByBomRef The mapping of BOM refs to {@link ComponentIdentity}s to populate
     * @param bomRefsByIdentity  The mapping of {@link ComponentIdentity}s to BOM refs to populate
     * @return A {@link Predicate} to use in {@link Stream#filter(Predicate)}
     */
    private static Predicate<Component> distinctComponentsByIdentity(final Map<String, ComponentIdentity> identitiesByBomRef,
                                                                     final MultiValuedMap<ComponentIdentity, String> bomRefsByIdentity) {
        final var identitiesSeen = new HashSet<ComponentIdentity>();

        return component -> {
            final var componentIdentity = new ComponentIdentity(component);
            identitiesByBomRef.putIfAbsent(component.getBomRef(), componentIdentity);
            bomRefsByIdentity.put(componentIdentity, component.getBomRef());
            return identitiesSeen.add(componentIdentity);
        };
    }

    /**
     * Factory for a stateful {@link Predicate} for de-duplicating {@link ServiceComponent}s based on their {@link ComponentIdentity}.
     * <p>
     * The predicate will populate {@code identitiesByBomRef} and {@code bomRefsByIdentity}.
     *
     * @param identitiesByBomRef The mapping of BOM refs to {@link ComponentIdentity}s to populate
     * @param bomRefsByIdentity  The mapping of {@link ComponentIdentity}s to BOM refs to populate
     * @return A {@link Predicate} to use in {@link Stream#filter(Predicate)}
     */
    private static Predicate<ServiceComponent> distinctServicesByIdentity(final Map<String, ComponentIdentity> identitiesByBomRef,
                                                                          final MultiValuedMap<ComponentIdentity, String> bomRefsByIdentity) {
        final var identitiesSeen = new HashSet<ComponentIdentity>();

        return service -> {
            final var componentIdentity = new ComponentIdentity(service);
            identitiesByBomRef.putIfAbsent(service.getBomRef(), componentIdentity);
            bomRefsByIdentity.put(componentIdentity, service.getBomRef());
            return identitiesSeen.add(componentIdentity);
        };
    }

    private void dispatchBomProcessedNotification(final Context ctx) {
        kafkaEventDispatcher.dispatchNotification(new Notification()
                .scope(NotificationScope.PORTFOLIO)
                .group(NotificationGroup.BOM_PROCESSED)
                .level(NotificationLevel.INFORMATIONAL)
                .title(NotificationConstants.Title.BOM_PROCESSED)
                .content("A %s BOM was processed".formatted(ctx.bomFormat.getFormatShortName()))
                // FIXME: Add reference to BOM after we have dedicated BOM server
                .subject(new BomConsumedOrProcessed(ctx.uploadToken, ctx.project, /* bom */ "(Omitted)", ctx.bomFormat, ctx.bomSpecVersion)));
    }

    /**
     * An {@link Exception} that signals failures during BOM processing.
     */
    private static final class BomProcessingException extends Exception {

        private final Context ctx;

        private BomProcessingException(final Context ctx, final String message, final Throwable cause) {
            super(message, cause);
            this.ctx = ctx;
        }

        private BomProcessingException(final Context ctx, final String message) {
            this(ctx, message, null);
        }

    }

    /**
     * An {@link Exception} that signals failures during BOM consumption.
     */
    private static final class BomConsumptionException extends Exception {

        private final Context ctx;

        private BomConsumptionException(final Context ctx, final String message, final Throwable cause) {
            super(message, cause);
            this.ctx = ctx;
        }

        private BomConsumptionException(final Context ctx, final String message) {
            this(ctx, message, null);
        }

    }

    /**
     * Context holder for identifiers and metadata that describe a processing execution.
     * Intended to be passed around and enriched during various stages of processing.
     */
    private static final class Context {

        private final Project project;
        private final UUID uploadToken;
        private Bom.Format bomFormat;
        private String bomSpecVersion;
        private String bomSerialNumber;
        private Integer bomVersion;

        private Context(final Project project, final UUID uploadToken) {
            this.project = project;
            this.uploadToken = uploadToken;
        }

        @Override
        public String toString() {
            return "Context{" +
                    "project=" + project.getUuid() +
                    ", uploadToken=" + uploadToken +
                    ", bomFormat=" + bomFormat +
                    ", bomSpecVersion=" + bomSpecVersion +
                    ", bomSerialNumber=" + bomSerialNumber +
                    ", bomVersion=" + bomVersion +
                    '}';
        }

    }

    private static boolean prepareIntegrityMetaComponent(ComponentRepositoryMetaAnalysisEvent event, QueryManager qm) {
        final IntegrityMetaComponent integrityMetaComponent = qm.getIntegrityMetaComponent(event.purlCoordinates());
        if (integrityMetaComponent == null) {
            qm.createIntegrityMetaHandlingConflict(AbstractMetaHandler.createIntegrityMetaComponent(event.purlCoordinates()));
            return true;
        } else if (integrityMetaComponent.getStatus() == null
                || (integrityMetaComponent.getStatus() == FetchStatus.IN_PROGRESS
                && (Date.from(Instant.now()).getTime() - integrityMetaComponent.getLastFetch().getTime()) > TIME_SPAN)) {
            integrityMetaComponent.setLastFetch(Date.from(Instant.now()));
            return true;
        } else if (integrityMetaComponent.getStatus() == FetchStatus.PROCESSED || integrityMetaComponent.getStatus() == FetchStatus.NOT_AVAILABLE) {
            EventService.getInstance().publish(new IntegrityAnalysisEvent(event.componentUuid(), integrityMetaComponent));
            return false;
        }
        //don't send event because integrity metadata would be sent recently and don't want to send again
        return false;
    }
}
