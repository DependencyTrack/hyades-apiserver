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
package org.dependencytrack.event.kafka.processor;

import alpine.common.logging.Logger;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import org.apache.commons.lang3.StringUtils;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.dependencytrack.event.kafka.processor.api.Processor;
import org.dependencytrack.event.kafka.processor.exception.ProcessingException;
import org.dependencytrack.model.FetchStatus;
import org.dependencytrack.model.IntegrityMetaComponent;
import org.dependencytrack.model.RepositoryMetaComponent;
import org.dependencytrack.model.RepositoryType;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.proto.repometaanalysis.v1.AnalysisResult;
import org.dependencytrack.util.PersistenceUtil;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import java.util.Date;
import java.util.Optional;

import static org.dependencytrack.event.kafka.componentmeta.IntegrityCheck.performIntegrityCheck;

/**
 * A {@link Processor} responsible for processing result of component repository meta analyses.
 */
public class RepositoryMetaResultProcessor implements Processor<String, AnalysisResult> {

    static final String PROCESSOR_NAME = "repo.meta.analysis.result";

    private static final Logger LOGGER = Logger.getLogger(RepositoryMetaResultProcessor.class);

    @Override
    public void process(final ConsumerRecord<String, AnalysisResult> record) throws ProcessingException {
        if (!isRecordValid(record)) {
            return;
        }
        try (final var qm = new QueryManager()) {
            synchronizeRepositoryMetadata(qm, record);
            IntegrityMetaComponent integrityMetaComponent = synchronizeIntegrityMetadata(qm, record);
            if (integrityMetaComponent != null) {
                performIntegrityCheck(integrityMetaComponent, record.value(), qm);
            }
        } catch (Exception e) {
            throw new ProcessingException(e);
        }
    }

    private IntegrityMetaComponent synchronizeIntegrityMetadata(final QueryManager queryManager, final ConsumerRecord<String, AnalysisResult> record) throws MalformedPackageURLException {
        final AnalysisResult result = record.value();
        PackageURL purl = new PackageURL(result.getComponent().getPurl());
        if (result.hasIntegrityMeta()) {
            return synchronizeIntegrityMetaResult(record, queryManager, purl);
        } else {
            LOGGER.debug("Incoming result for component with purl %s  does not include component integrity info".formatted(purl));
            return null;
        }
    }

    private void synchronizeRepositoryMetadata(final QueryManager qm, final ConsumerRecord<String, AnalysisResult> record) throws Exception {
        final PersistenceManager pm = qm.getPersistenceManager();
        final AnalysisResult result = record.value();
        final var purl = new PackageURL(result.getComponent().getPurl());

        // It is possible that the same meta info is reported for multiple components in parallel,
        // causing unique constraint violations when attempting to insert into the REPOSITORY_META_COMPONENT table.
        // In such cases, we can get away with simply retrying to SELECT+UPDATE or INSERT again. We'll attempt
        // up to 3 times before giving up.
        qm.runInRetryableTransaction(() -> {
            final RepositoryMetaComponent repositoryMetaComponentResult = createRepositoryMetaResult(record, pm, purl);
            if (repositoryMetaComponentResult != null) {
                pm.makePersistent(repositoryMetaComponentResult);
            }

            return null;
        }, PersistenceUtil::isUniqueConstraintViolation);
    }

    private RepositoryMetaComponent createRepositoryMetaResult(ConsumerRecord<String, AnalysisResult> incomingAnalysisResultRecord, PersistenceManager pm, PackageURL purl) {
        final AnalysisResult result = incomingAnalysisResultRecord.value();
        if (!result.hasLatestVersion()) {
            return null;
        }

        final Query<RepositoryMetaComponent> query = pm.newQuery(RepositoryMetaComponent.class);
        query.setFilter("repositoryType == :repositoryType && namespace == :namespace && name == :name");
        query.setParameters(
                RepositoryType.resolve(purl),
                purl.getNamespace(),
                purl.getName()
        );

        RepositoryMetaComponent persistentRepoMetaComponent;
        try {
            persistentRepoMetaComponent = query.executeUnique();
        } finally {
            query.closeAll();
        }

        if (persistentRepoMetaComponent == null) {
            persistentRepoMetaComponent = new RepositoryMetaComponent();
        }

        if (persistentRepoMetaComponent.getLastCheck() != null
            && persistentRepoMetaComponent.getLastCheck().after(new Date(incomingAnalysisResultRecord.timestamp()))) {
            LOGGER.warn("""
                    Received repository meta information for %s that is older\s
                    than what's already in the database; Discarding
                    """.formatted(purl));
            return null;
        }

        persistentRepoMetaComponent.setRepositoryType(RepositoryType.resolve(purl));
        persistentRepoMetaComponent.setNamespace(purl.getNamespace());
        persistentRepoMetaComponent.setName(purl.getName());
        if (result.hasLatestVersion()) {
            persistentRepoMetaComponent.setLatestVersion(result.getLatestVersion());
        }
        if (result.hasPublished()) {
            persistentRepoMetaComponent.setPublished(new Date(result.getPublished().getSeconds() * 1000));
        }
        persistentRepoMetaComponent.setLastCheck(new Date(incomingAnalysisResultRecord.timestamp()));
        return persistentRepoMetaComponent;
    }

    private IntegrityMetaComponent synchronizeIntegrityMetaResult(final ConsumerRecord<String, AnalysisResult> incomingAnalysisResultRecord, QueryManager queryManager, PackageURL purl) {
        final AnalysisResult result = incomingAnalysisResultRecord.value();
        IntegrityMetaComponent persistentIntegrityMetaComponent = queryManager.getIntegrityMetaComponent(purl.toString());
        if (persistentIntegrityMetaComponent != null && persistentIntegrityMetaComponent.getStatus() != null && persistentIntegrityMetaComponent.getStatus().equals(FetchStatus.PROCESSED)) {
            LOGGER.warn("""
                    Received hash information for %s that has already been processed; Discarding
                    """.formatted(purl));
            return persistentIntegrityMetaComponent;
        }
        if (persistentIntegrityMetaComponent == null) {
            persistentIntegrityMetaComponent = new IntegrityMetaComponent();
        }

        if (result.getIntegrityMeta().hasMd5() || result.getIntegrityMeta().hasSha1() || result.getIntegrityMeta().hasSha256()
                || result.getIntegrityMeta().hasSha512() || result.getIntegrityMeta().hasCurrentVersionLastModified()) {
            Optional.of(result.getIntegrityMeta().getMd5()).filter(StringUtils::isNotBlank).ifPresent(persistentIntegrityMetaComponent::setMd5);
            Optional.of(result.getIntegrityMeta().getSha1()).filter(StringUtils::isNotBlank).ifPresent(persistentIntegrityMetaComponent::setSha1);
            Optional.of(result.getIntegrityMeta().getSha256()).filter(StringUtils::isNotBlank).ifPresent(persistentIntegrityMetaComponent::setSha256);
            Optional.of(result.getIntegrityMeta().getSha512()).filter(StringUtils::isNotBlank).ifPresent(persistentIntegrityMetaComponent::setSha512);
            persistentIntegrityMetaComponent.setPurl(result.getComponent().getPurl());
            persistentIntegrityMetaComponent.setRepositoryUrl(result.getIntegrityMeta().getMetaSourceUrl());
            persistentIntegrityMetaComponent.setPublishedAt(result.getIntegrityMeta().hasCurrentVersionLastModified() ? new Date(result.getIntegrityMeta().getCurrentVersionLastModified().getSeconds() * 1000) : null);
            persistentIntegrityMetaComponent.setStatus(FetchStatus.PROCESSED);
        } else {
            persistentIntegrityMetaComponent.setMd5(null);
            persistentIntegrityMetaComponent.setSha256(null);
            persistentIntegrityMetaComponent.setSha1(null);
            persistentIntegrityMetaComponent.setSha512(null);
            persistentIntegrityMetaComponent.setPurl(purl.toString());
            persistentIntegrityMetaComponent.setRepositoryUrl(result.getIntegrityMeta().getMetaSourceUrl());
            persistentIntegrityMetaComponent.setStatus(FetchStatus.NOT_AVAILABLE);
        }
        return queryManager.updateIntegrityMetaComponent(persistentIntegrityMetaComponent);
    }

    private static boolean isRecordValid(final ConsumerRecord<String, AnalysisResult> record) {
        final AnalysisResult result = record.value();
        if (!result.hasComponent()) {
            LOGGER.warn("""
                    Received repository meta information without component,\s
                    will not be able to correlate; Dropping
                    """);
            return false;
        }

        try {
            new PackageURL(result.getComponent().getPurl());
        } catch (MalformedPackageURLException e) {
            LOGGER.warn("""
                    Received repository meta information with invalid PURL,\s
                    will not be able to correlate; Dropping
                    """, e);
            return false;
        }
        return true;
    }
}
