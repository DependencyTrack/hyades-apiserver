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
import com.google.protobuf.util.Timestamps;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.dependencytrack.event.kafka.processor.api.BatchProcessor;
import org.dependencytrack.event.kafka.processor.api.Processor;
import org.dependencytrack.event.kafka.processor.exception.ProcessingException;
import org.dependencytrack.model.FetchStatus;
import org.dependencytrack.model.IntegrityMetaComponent;
import org.dependencytrack.model.RepositoryMetaComponent;
import org.dependencytrack.model.RepositoryType;
import org.dependencytrack.persistence.jdbi.MetaComponentDao;
import org.dependencytrack.proto.repometaanalysis.v1.AnalysisResult;
import org.dependencytrack.util.PurlUtil;

import java.util.Comparator;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.apache.commons.lang3.StringUtils.trimToNull;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiHandle;

/**
 * A {@link Processor} responsible for processing result of component repository meta analyses.
 */
public class RepositoryMetaResultProcessor implements BatchProcessor<String, AnalysisResult> {

    static final String PROCESSOR_NAME = "repo.meta.analysis.result";

    private static final Logger LOGGER = Logger.getLogger(RepositoryMetaResultProcessor.class);

    @Override
    public void process(final List<ConsumerRecord<String, AnalysisResult>> records) throws ProcessingException {
        final List<ConsumerRecord<String, AnalysisResult>> validRecords = records.stream()
                .filter(RepositoryMetaResultProcessor::isRecordValid)
                .toList();
        if (validRecords.isEmpty()) {
            return;
        }

        final List<RepositoryMetaComponent> repoMetaComponents = createRepositoryMetaComponents(records);
        final List<IntegrityMetaComponent> integrityMetaComponents = createIntegrityMetaComponents(records);

        final Map<RepositoryMetaComponent.Identity, RepositoryMetaComponent> repositoryMetaComponentByIdentity = repoMetaComponents.stream()
                .collect(Collectors.toMap(RepositoryMetaComponent.Identity::of, Function.identity()));
        final Map<String, IntegrityMetaComponent> integrityMetaComponentByPurl = integrityMetaComponents.stream()
                .collect(Collectors.toMap(IntegrityMetaComponent::getPurl, Function.identity()));

        useJdbiHandle(handle -> {
            final var dao = handle.attach(MetaComponentDao.class);

            handle.useTransaction(ignored -> {
                final List<RepositoryMetaComponent.Identity> identitiesCreated = dao.createAllRepositoryMetaComponents(repoMetaComponents);
                identitiesCreated.forEach(repositoryMetaComponentByIdentity::remove);

                final List<RepositoryMetaComponent.Identity> identitiesUpdated = dao.updateAllRepositoryMetaComponents(repoMetaComponents);
                identitiesUpdated.forEach(repositoryMetaComponentByIdentity::remove);
            });

            handle.useTransaction(ignored -> {
                final List<String> purlsCreated = dao.createAllIntegrityMetaComponents(integrityMetaComponents);
                purlsCreated.forEach(integrityMetaComponentByPurl::remove);

                final List<String> purlsUpdated = dao.updateAllIntegrityMetaComponents(integrityMetaComponents);
                purlsUpdated.forEach(integrityMetaComponentByPurl::remove);
            });
        });

        // TODO: Execute integrity check for created or modified IntegrityMetaComponents

        if (LOGGER.isDebugEnabled()) {
            if (!repoMetaComponents.isEmpty()) {
                LOGGER.debug("%d repository meta components where not created or updated".formatted(repoMetaComponents.size()));
            }
            if (!integrityMetaComponents.isEmpty()) {
                LOGGER.debug("%s integrity meta components were not created or updated".formatted(integrityMetaComponents.size()));
            }
        }
    }

    private List<RepositoryMetaComponent> createRepositoryMetaComponents(final List<ConsumerRecord<String, AnalysisResult>> records) {
        final var identitiesSeen = new HashSet<RepositoryMetaComponent.Identity>();
        return records.stream()
                .map(RepositoryMetaResultProcessor::createRepositoryMetaComponent)
                // Sort by lastFetch such that later timestamps appear first.
                .sorted(Comparator.comparing(RepositoryMetaComponent::getLastCheck).reversed())
                // Keep only one (the latest) meta component for each repoType-namespace-name triplet.
                .filter(metaComponent -> identitiesSeen.add(RepositoryMetaComponent.Identity.of(metaComponent)))
                .toList();
    }

    private static RepositoryMetaComponent createRepositoryMetaComponent(final ConsumerRecord<String, AnalysisResult> record) {
        final var checkTimestamp = new Date(record.timestamp());
        final AnalysisResult result = record.value();
        final var purl = PurlUtil.silentPurl(result.getComponent().getPurl());

        final var metaComponent = new RepositoryMetaComponent();
        metaComponent.setRepositoryType(RepositoryType.resolve(purl));
        metaComponent.setNamespace(purl.getNamespace());
        metaComponent.setName(purl.getName());
        metaComponent.setLatestVersion(result.getLatestVersion());
        metaComponent.setPublished(new Date(Timestamps.toMillis(result.getPublished())));
        metaComponent.setLastCheck(checkTimestamp);
        return metaComponent;
    }

    private static List<IntegrityMetaComponent> createIntegrityMetaComponents(final List<ConsumerRecord<String, AnalysisResult>> records) {
        final var purlsSeen = new HashSet<String>();
        return records.stream()
                .filter(record -> record.value().hasIntegrityMeta())
                .map(RepositoryMetaResultProcessor::createIntegrityMetaComponent)
                // Sort by lastFetch such that later timestamps appear first.
                .sorted(Comparator.comparing(IntegrityMetaComponent::getLastFetch).reversed())
                // Only keep one (the latest) meta component for each PURL.
                .filter(metaComponent -> purlsSeen.add(metaComponent.getPurl()))
                .toList();
    }

    private static IntegrityMetaComponent createIntegrityMetaComponent(final ConsumerRecord<String, AnalysisResult> record) {
        final var checkTimestamp = new Date(record.timestamp());
        final AnalysisResult result = record.value();

        final var metaComponent = new IntegrityMetaComponent();
        metaComponent.setPurl(result.getComponent().getPurl());
        metaComponent.setRepositoryUrl(result.getIntegrityMeta().getMetaSourceUrl());
        metaComponent.setMd5(trimToNull(result.getIntegrityMeta().getMd5()));
        metaComponent.setSha1(trimToNull(result.getIntegrityMeta().getSha1()));
        metaComponent.setSha256(trimToNull(result.getIntegrityMeta().getSha256()));
        metaComponent.setSha512(trimToNull(result.getIntegrityMeta().getSha512()));
        if (result.getIntegrityMeta().hasCurrentVersionLastModified()) {
            metaComponent.setPublishedAt(new Date(Timestamps.toMillis(result.getIntegrityMeta().getCurrentVersionLastModified())));
        }
        if (metaComponent.getMd5() != null
            || metaComponent.getSha1() != null
            || metaComponent.getSha256() != null
            || metaComponent.getSha512() != null) {
            metaComponent.setStatus(FetchStatus.PROCESSED);
        } else {
            metaComponent.setStatus(FetchStatus.NOT_AVAILABLE);
        }
        metaComponent.setLastFetch(checkTimestamp);
        return metaComponent;
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
