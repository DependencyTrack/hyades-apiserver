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
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ComponentIdentity;
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
import org.dependencytrack.persistence.FlushHelper;
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
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
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
    private static final int FLUSH_THRESHOLD = 10000;

    private final KafkaEventDispatcher kafkaEventDispatcher;

    public BomUploadProcessingTask() {
        this(new KafkaEventDispatcher());
    }

    BomUploadProcessingTask(final KafkaEventDispatcher kafkaEventDispatcher) {
        this.kafkaEventDispatcher = kafkaEventDispatcher;
    }

    public void inform(final Event e) {
        if (e instanceof final BomUploadEvent event) {
            final var ctx = new Context(event.getProject(), event.getChainIdentifier());
            final Timer.Sample timerSample = Timer.start();
            try {
                process(ctx, event);
            } catch (BomProcessingException ex) {
                kafkaEventDispatcher.dispatchAsync(ex.ctx.project.getUuid(), new Notification()
                        .scope(NotificationScope.PORTFOLIO)
                        .group(NotificationGroup.BOM_PROCESSING_FAILED)
                        .level(NotificationLevel.ERROR)
                        .title(NotificationConstants.Title.BOM_PROCESSING_FAILED)
                        .content("An error occurred while processing a BOM")
                        // FIXME: Add reference to BOM after we have dedicated BOM server
                        .subject(new BomProcessingFailed(ctx.project, /* bom */ "(Omitted)", "%s (%s)".formatted(ex.getMessage(), ex.ctx), ex.ctx.bomFormat, ex.ctx.bomSpecVersion)));
            } catch (Exception ex) {
                kafkaEventDispatcher.dispatchAsync(ctx.project.getUuid(), new Notification()
                        .scope(NotificationScope.PORTFOLIO)
                        .group(NotificationGroup.BOM_PROCESSING_FAILED)
                        .level(NotificationLevel.ERROR)
                        .title(NotificationConstants.Title.BOM_PROCESSING_FAILED)
                        .content("An error occurred while processing a BOM")
                        // FIXME: Add reference to BOM after we have dedicated BOM server
                        .subject(new BomProcessingFailed(ctx.project, /* bom */ "(Omitted)", ex.getMessage(), ctx.bomFormat /* (may be null) */, ctx.bomSpecVersion /* (may be null) */)));
            } finally {
                timerSample.stop(TIMER);
            }
        }
    }

    void process(final Context ctx, final BomUploadEvent event) throws BomProcessingException {
        LOGGER.info("Consuming uploaded BOM (%s)".formatted(ctx));
        final org.cyclonedx.model.Bom cdxBom = parseBom(ctx, event);

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
        final var componentIdentitiesByBomRef = new HashMap<String, ComponentIdentity>();

        final List<Component> components = flattenComponents(convertComponents(cdxBom.getComponents())).stream()
                .filter(distinctComponentByIdentity(componentIdentitiesByBomRef))
                .toList();
        final List<ServiceComponent> serviceComponents = flattenServices(convertServices(cdxBom.getServices())).stream()
                .filter(distinctServiceByIdentity(componentIdentitiesByBomRef))
                .toList();

        kafkaEventDispatcher.dispatchAsync(ctx.project.getUuid(), new Notification()
                .scope(NotificationScope.PORTFOLIO)
                .group(NotificationGroup.BOM_CONSUMED)
                .level(NotificationLevel.INFORMATIONAL)
                .title(NotificationConstants.Title.BOM_CONSUMED)
                .content("A %s BOM was consumed and will be processed".formatted(ctx.bomFormat.getFormatShortName()))
                .subject(new BomConsumedOrProcessed(ctx.project, /* bom */ "(Omitted)", ctx.bomFormat, ctx.bomSpecVersion)));

        final var vulnAnalysisEvents = new ArrayList<ComponentVulnerabilityAnalysisEvent>();
        final var repoMetaAnalysisEvents = new ArrayList<ComponentRepositoryMetaAnalysisEvent>();

        try (final var qm = new QueryManager()) {
            final PersistenceManager pm = qm.getPersistenceManager();
            pm.setProperty(PropertyNames.PROPERTY_PERSISTENCE_BY_REACHABILITY_AT_COMMIT, "false");

            // Save some database round-trips by only flushing changes every "flushThreshold" write operations.
            // See https://www.datanucleus.org/products/accessplatform_4_1/jdo/performance_tuning.html
            pm.setProperty(PropertyNames.PROPERTY_FLUSH_MODE, FlushMode.MANUAL.name());

            LOGGER.info("Processing %d components and %d services from BOM (%s)"
                    .formatted(components.size(), serviceComponents.size(), ctx));

            final Transaction trx = pm.currentTransaction();
            try {
                trx.begin();

                final Project project = processMetadataComponent(ctx, pm, metadataComponent);

                final Map<ComponentIdentity, Component> persistentComponents =
                        processComponents(ctx, qm, project, components, componentIdentitiesByBomRef);

                processDependencyGraph(ctx, pm, cdxBom, project, persistentComponents, componentIdentitiesByBomRef);

                LOGGER.info("Creating record for processed BOM (%s)".formatted(ctx));
                final var bom = new Bom();
                bom.setProject(project);
                bom.setBomFormat(ctx.bomFormat);
                bom.setSpecVersion(ctx.bomSpecVersion);
                bom.setSerialNumber(ctx.bomSerialNumber);
                bom.setBomVersion(ctx.bomVersion);
                bom.setImported(new Date());
                pm.makePersistent(bom);

                project.setLastBomImport(bom.getImported());
                project.setLastBomImportFormat(bom.getBomFormat());

                for (final Component component : persistentComponents.values()) {
                    // Note: component does not need to be detached.
                    // The constructors of ComponentRepositoryMetaAnalysisEvent ComponentVulnerabilityAnalysisEvent
                    // merely call a few getters on it, but the component object itself is not passed around.
                    // Detaching would imply additional database interactions that we'd rather not do.
                    repoMetaAnalysisEvents.add(new ComponentRepositoryMetaAnalysisEvent(component));
                    vulnAnalysisEvents.add(new ComponentVulnerabilityAnalysisEvent(
                            event.getChainIdentifier(), component, VulnerabilityAnalysisLevel.BOM_UPLOAD_ANALYSIS));
                }

                trx.commit();
            } finally {
                if (trx.isActive()) {
                    LOGGER.warn("Rolling back uncommitted transaction (%s)".formatted(ctx));
                    trx.rollback();
                }
            }

            if (!vulnAnalysisEvents.isEmpty()) {
                qm.createVulnerabilityScan(TargetType.PROJECT, ctx.project.getUuid(), ctx.uploadToken.toString(), vulnAnalysisEvents.size());
                vulnAnalysisEvents.forEach(kafkaEventDispatcher::dispatchAsync);
            }

            repoMetaAnalysisEvents.forEach(kafkaEventDispatcher::dispatchAsync);

            // TODO: Trigger index updates
        }

        LOGGER.info("BOM processed successfully (%s)".formatted(ctx));
        kafkaEventDispatcher.dispatchAsync(ctx.project.getUuid(), new Notification()
                .scope(NotificationScope.PORTFOLIO)
                .group(NotificationGroup.BOM_PROCESSED)
                .level(NotificationLevel.INFORMATIONAL)
                .title(NotificationConstants.Title.BOM_PROCESSED)
                .content("A %s BOM was processed".formatted(ctx.bomFormat.getFormatShortName()))
                // FIXME: Add reference to BOM after we have dedicated BOM server
                .subject(new BomConsumedOrProcessed(ctx.project, /* bom */ "(Omitted)", ctx.bomFormat, ctx.bomSpecVersion)));
    }

    private static Project processMetadataComponent(final Context ctx, final PersistenceManager pm, final Project metadataComponent) throws BomProcessingException {
        final Query<Project> query = pm.newQuery(Project.class);
        query.setFilter("uuid == :uuid");
        query.setParameters(ctx.project.getUuid());

        final Project project;
        try {
            project = query.executeUnique();
        } finally {
            query.closeAll();
        }
        if (project == null) {
            throw new BomProcessingException(ctx, "Project does not exist");
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
            projectChanged |= applyIfChanged(project, metadataComponent, Project::getExternalReferences, project::setExternalReferences);
            projectChanged |= applyIfChanged(project, metadataComponent, Project::getPurl, project::setPurl);
            projectChanged |= applyIfChanged(project, metadataComponent, Project::getSwidTagId, project::setSwidTagId);
            if (projectChanged) {
                pm.flush();
            }
        }

        return project;
    }

    private static Map<ComponentIdentity, Component> processComponents(final Context ctx, final QueryManager qm,
                                                                       final Project project, final List<Component> components,
                                                                       final Map<String, ComponentIdentity> componentIdentityBomRefs) {
        final PersistenceManager pm = qm.getPersistenceManager();

        // Fetch IDs of all components that exist in the project already.
        // We'll need them later to determine which components to delete.
        final Set<Long> oldComponentIds = getAllComponentIds(pm, project);

        // Avoid redundant queries by caching resolved licenses.
        final var licenseCache = new HashMap<String, License>();

        final var persistentComponents = new HashMap<ComponentIdentity, Component>();
        try (final var flushHelper = new FlushHelper(qm, FLUSH_THRESHOLD)) {
            for (final Component component : components) {
                component.setInternal(isInternalComponent(component, qm));

                // Try to resolve the license by its ID.
                // Note: licenseId is a transient field of Component and will not survive this transaction.
                if (component.getLicenseId() != null) {
                    component.setResolvedLicense(resolveLicense(pm, licenseCache, component.getLicenseId()));
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

                if (isNewOrUpdated) { // Flushing is only necessary when something changed
                    flushHelper.maybeFlush();
                }
            }
        }

        // License cache is no longer needed; Let go of it.
        licenseCache.clear();

        // Delete components that existed before this BOM import, but do not exist anymore.
        deleteComponentsById(pm, oldComponentIds);

        return persistentComponents;
    }

    private static void processDependencyGraph(final Context ctx, final PersistenceManager pm, final org.cyclonedx.model.Bom cdxBom,
                                               final Project project, final Map<ComponentIdentity, Component> componentsByIdentity,
                                               final Map<String, ComponentIdentity> componentIdentitiesByBomRef) {
        if (cdxBom.getMetadata() != null
                && cdxBom.getMetadata().getComponent() != null
                && cdxBom.getMetadata().getComponent().getBomRef() != null) {
            final org.cyclonedx.model.Dependency metadataComponentDependency =
                    findDependencyByBomRef(cdxBom.getDependencies(), cdxBom.getMetadata().getComponent().getBomRef());

            final var jsonDependencies = new JSONArray();
            if (metadataComponentDependency != null && metadataComponentDependency.getDependencies() != null) {
                for (final org.cyclonedx.model.Dependency dependency : metadataComponentDependency.getDependencies()) {
                    final ComponentIdentity dependencyIdentity = componentIdentitiesByBomRef.get(dependency.getRef());
                    if (dependencyIdentity != null) {
                        jsonDependencies.put(dependencyIdentity.toJSON());
                    } else {
                        LOGGER.warn("BOM ref " + dependency.getRef() + " does not match any component identity");
                    }
                }
            }

            final var jsonDependenciesStr = jsonDependencies.isEmpty() ? null : jsonDependencies.toString();
            if (!Objects.equals(jsonDependenciesStr, project.getDirectDependencies())) {
                project.setDirectDependencies(jsonDependenciesStr);
                pm.flush();
            }
        }

        try (final var flushHelper = new FlushHelper(pm, FLUSH_THRESHOLD)) {
            for (final Map.Entry<String, ComponentIdentity> entry : componentIdentitiesByBomRef.entrySet()) {
                final ComponentIdentity identity = componentIdentitiesByBomRef.get(entry.getKey());
                final org.cyclonedx.model.Dependency dependency = findDependencyByBomRef(cdxBom.getDependencies(), entry.getKey());

                final var jsonDependencies = new JSONArray();
                if (dependency != null && dependency.getDependencies() != null) {
                    for (final org.cyclonedx.model.Dependency dependency1 : dependency.getDependencies()) {
                        final ComponentIdentity dependencyIdentity = componentIdentitiesByBomRef.get(dependency1.getRef());
                        if (dependencyIdentity != null) {
                            jsonDependencies.put(dependencyIdentity.toJSON());
                        } else {
                            LOGGER.warn("BOM ref " + dependency.getRef() + " does not match any component identity");
                        }
                    }
                }

                final var jsonDependenciesStr = jsonDependencies.isEmpty() ? null : jsonDependencies.toString();
                final Component persistentComponent = componentsByIdentity.get(identity);
                if (persistentComponent != null) {
                    if (!Objects.equals(jsonDependenciesStr, persistentComponent.getDirectDependencies())) {
                        persistentComponent.setDirectDependencies(jsonDependenciesStr);
                        flushHelper.maybeFlush();
                    }
                } else {
                    LOGGER.warn("""
                            Unable to resolve component identity %s to a persistent component; \
                            As a result, the dependency graph of project %s will likely be incomplete (%s)"""
                            .formatted(identity.toJSON(), ctx.project, ctx));
                }
            }
        }
    }

    private static void deleteComponentsById(final PersistenceManager pm, final Set<Long> componentIds) {
        if (componentIds.isEmpty()) {
            return;
        }

        try (final var flushHelper = new FlushHelper(pm, FLUSH_THRESHOLD)) {
            for (final Long componentId : componentIds) {
                // TODO: Re-implement qm.recursivelyDelete so that it uses the current active
                //   transaction instead of creating and committing its own. The following delete
                //   will fail due to FK constraints when there are metrics etc. associated with
                //   the component.
                final Query<Component> componentDeleteQuery = pm.newQuery(Component.class);
                try {
                    componentDeleteQuery.setFilter("id == :id");
                    componentDeleteQuery.deletePersistentAll(componentId);
                } finally {
                    componentDeleteQuery.closeAll();
                }

                flushHelper.maybeFlush();
            }
        }
    }

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

    private org.cyclonedx.model.Bom parseBom(final Context ctx, final BomUploadEvent event) throws BomProcessingException {
        final byte[] bomBytes;
        try (final var bomFileInputStream = Files.newInputStream(event.getFile().toPath(), StandardOpenOption.DELETE_ON_CLOSE)) {
            bomBytes = bomFileInputStream.readAllBytes();
        } catch (IOException e) {
            throw new BomProcessingException(ctx, "Failed to read BOM file", e);
        }

        if (!BomParserFactory.looksLikeCycloneDX(bomBytes)) {
            throw new BomProcessingException(ctx, """
                    The BOM uploaded is not in a supported format. \
                    Supported formats include CycloneDX XML and JSON""");
        }

        ctx.bomFormat = Bom.Format.CYCLONEDX;

        final org.cyclonedx.model.Bom bom;
        try {
            final Parser parser = BomParserFactory.createParser(bomBytes);
            bom = parser.parse(bomBytes);
        } catch (ParseException e) {
            throw new BomProcessingException(ctx, "Failed to parse BOM", e);
        }

        ctx.bomSpecVersion = bom.getSpecVersion();
        if (bom.getSerialNumber() != null) {
            ctx.bomSerialNumber = bom.getSerialNumber().replaceFirst("urn:uuid:", "");
        }
        ctx.bomVersion = bom.getVersion();

        return bom;
    }

    private static Set<Long> getAllComponentIds(final PersistenceManager pm, final Project project) {
        final Query<Component> query = pm.newQuery(Component.class);
        query.setFilter("project == :project");
        query.setParameters(project);
        query.setResult("id");

        try {
            return new HashSet<>(query.executeResultList(Long.class));
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
                    ", bomSpecVersion='" + bomSpecVersion + '\'' +
                    ", bomSerialNumber='" + bomSerialNumber + '\'' +
                    ", bomVersion=" + bomVersion +
                    '}';
        }

    }

}
