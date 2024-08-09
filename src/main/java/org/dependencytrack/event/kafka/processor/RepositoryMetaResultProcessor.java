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

import alpine.Config;
import alpine.common.logging.Logger;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import com.google.protobuf.Timestamp;
import com.google.protobuf.util.Timestamps;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.dependencytrack.common.ConfigKey;
import org.dependencytrack.event.kafka.processor.api.BatchProcessor;
import org.dependencytrack.event.kafka.processor.api.Processor;
import org.dependencytrack.event.kafka.processor.exception.ProcessingException;
import org.dependencytrack.model.FetchStatus;
import org.dependencytrack.model.IntegrityMetaComponent;
import org.dependencytrack.model.RepositoryMetaComponent;
import org.dependencytrack.model.RepositoryType;
import org.dependencytrack.persistence.jdbi.ComponentMetaDao;
import org.dependencytrack.proto.repometaanalysis.v1.AnalysisResult;
import org.dependencytrack.proto.repometaanalysis.v1.IntegrityMeta;
import org.dependencytrack.util.PurlUtil;

import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.apache.commons.lang3.StringUtils.trimToNull;
import static org.apache.commons.lang3.time.DateFormatUtils.ISO_8601_EXTENDED_DATETIME_TIME_ZONE_FORMAT;
import static org.dependencytrack.event.kafka.processor.api.ProcessorUtils.withEnrichedMdc;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiHandle;

/**
 * A {@link Processor} responsible for processing result of component repository meta analyses.
 */
public class RepositoryMetaResultProcessor implements BatchProcessor<String, AnalysisResult> {

    static final String PROCESSOR_NAME = "repo.meta.analysis.result";

    private static final Logger LOGGER = Logger.getLogger(RepositoryMetaResultProcessor.class);

    @Override
    public void process(final List<ConsumerRecord<String, AnalysisResult>> records) throws ProcessingException {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Consumed batch of %d record(s)".formatted(records.size()));
        }

        final List<ConsumerRecord<String, AnalysisResult>> validRecords = records.stream()
                .filter(record -> withEnrichedMdc(record, () -> isRecordValid(record)))
                .toList();
        if (validRecords.isEmpty()) {
            LOGGER.warn("None of the %d consumed record(s) are valid; Skipping".formatted(records.size()));
            return;
        }

        final Map<RepositoryMetaComponent.Identity, RepositoryMetaComponent> repoMetaComponentByIdentity = createRepoMetaComponents(records);
        final Map<String, IntegrityMetaComponent> integrityMetaComponentByPurl = createIntegrityMetaComponents(records);

        useJdbiHandle(handle -> {
            final var dao = handle.attach(ComponentMetaDao.class);
            handle.useTransaction(ignored -> processRepositoryMetaComponents(dao, repoMetaComponentByIdentity));
            handle.useTransaction(ignored -> processIntegrityMetaComponents(dao, integrityMetaComponentByPurl));
        });
    }

    private void processRepositoryMetaComponents(
            final ComponentMetaDao dao,
            final Map<RepositoryMetaComponent.Identity, RepositoryMetaComponent> metaComponentByIdentity
    ) {
        final var unprocessedMetaComponentByIdentity = new HashMap<>(metaComponentByIdentity);

        final List<RepositoryMetaComponent.Identity> createdIdentities =
                dao.createAllRepositoryMetaComponents(unprocessedMetaComponentByIdentity.values());
        createdIdentities.forEach(unprocessedMetaComponentByIdentity::remove);

        final List<RepositoryMetaComponent.Identity> updatedIdentities =
                dao.updateAllRepositoryMetaComponents(unprocessedMetaComponentByIdentity.values());
        updatedIdentities.forEach(unprocessedMetaComponentByIdentity::remove);

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Processed repository meta component records: {created=%d, updated=%d, unchanged=%d}"
                    .formatted(createdIdentities.size(), updatedIdentities.size(), unprocessedMetaComponentByIdentity.size()));
        }
    }

    private void processIntegrityMetaComponents(
            final ComponentMetaDao dao,
            final Map<String, IntegrityMetaComponent> metaComponentByPurl
    ) {
        final var modifiedMetaComponentPurls = new HashSet<String>();
        final var unprocessedMetaComponentByPurl = new HashMap<>(metaComponentByPurl);

        int numCreated = 0;
        for (final String purl : dao.createAllIntegrityMetaComponents(unprocessedMetaComponentByPurl.values())) {
            unprocessedMetaComponentByPurl.remove(purl);
            modifiedMetaComponentPurls.add(purl);
            numCreated++;
        }

        int numUpdated = 0;
        if (!unprocessedMetaComponentByPurl.isEmpty()) {
            for (final String purl : dao.updateAllIntegrityMetaComponents(unprocessedMetaComponentByPurl.values())) {
                unprocessedMetaComponentByPurl.remove(purl);
                modifiedMetaComponentPurls.add(purl);
                numUpdated++;
            }
        }

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Processed integrity meta component records: {created=%d, updated=%d, unchanged=%d}"
                    .formatted(numCreated, numUpdated, unprocessedMetaComponentByPurl.size()));
        }

        if (!Config.getInstance().getPropertyAsBoolean(ConfigKey.INTEGRITY_CHECK_ENABLED)
            || (modifiedMetaComponentPurls.isEmpty())) {
            return;
        }

        // NB: Doing this here COULD, POTENTIALLY, EVENTUALLY cause the transaction to take too long.
        // Depends on overall size of portfolio, the number of records in this batch, as well as the
        // number of distinct PURLs in the batch.
        //
        // If this ever turns out to be problematic, we will need to switch to processing
        // INTEGRITY_META_COMPONENT records and INTEGRITY_ANALYSIS one-by-one, rather than in batches.
        // Persisting of meta component and analysis must be atomic.
        //
        // Reason being that if persisting of meta component record succeeds, but integrity analysis fails
        // due to a transient error, we must ensure that retrying the processing of the Kafka record achieves
        // the same result. If we do persisting and analysis in separate transactions, the analysis would not
        // be repeated upon retry, since the meta component record is not registered as "modified" anymore.
        final int modifiedAnalyses = dao.createOrUpdateIntegrityAnalysesForPurls(modifiedMetaComponentPurls);
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Created or updated %d integrity analyses for %s"
                    .formatted(modifiedAnalyses, modifiedMetaComponentPurls));
        }
    }

    @SuppressWarnings("RedundantStreamOptionalCall") // Calling .sorted before .collect is intentional.
    private Map<RepositoryMetaComponent.Identity, RepositoryMetaComponent> createRepoMetaComponents(
            final List<ConsumerRecord<String, AnalysisResult>> records
    ) {
        final var identitiesSeen = new HashSet<RepositoryMetaComponent.Identity>();
        return records.stream()
                // We only store meta components for which the latest version was reported.
                .filter(record -> record.value().hasLatestVersion())
                .map(record -> withEnrichedMdc(record, () -> createRepoMetaComponent(record)))
                // Sort by lastFetch such that later timestamps appear first.
                .sorted(Comparator.comparing(RepositoryMetaComponent::getLastCheck).reversed())
                // Keep only one (the latest) meta component for each repoType-namespace-name triplet.
                .filter(metaComponent -> identitiesSeen.add(RepositoryMetaComponent.Identity.of(metaComponent)))
                .collect(Collectors.toMap(RepositoryMetaComponent.Identity::of, Function.identity()));
    }

    private static RepositoryMetaComponent createRepoMetaComponent(final ConsumerRecord<String, AnalysisResult> record) {
        final AnalysisResult result = record.value();
        final PackageURL purl = PurlUtil.silentPurl(result.getComponent().getPurl());

        final var metaComponent = new RepositoryMetaComponent();
        metaComponent.setRepositoryType(RepositoryType.resolve(purl));
        metaComponent.setNamespace(purl.getNamespace());
        metaComponent.setName(purl.getName());
        metaComponent.setLatestVersion(result.getLatestVersion());
        if (result.hasPublished()) {
            metaComponent.setPublished(new Date(Timestamps.toMillis(result.getPublished())));
        }
        if (result.getFetchedAt() != Timestamp.getDefaultInstance()) {
            metaComponent.setLastCheck(new Date(Timestamps.toMillis(result.getFetchedAt())));
        } else {
            // For records sent by repository-meta-analyzer <=0.5.0.
            final var recordTimestamp = new Date(record.timestamp());
            LOGGER.warn("""
                    No fetched_at timestamp provided for repository metadata, \
                    assuming record timestamp %s instead\
                    """.formatted(ISO_8601_EXTENDED_DATETIME_TIME_ZONE_FORMAT.format(recordTimestamp)));
            metaComponent.setLastCheck(recordTimestamp);
        }
        return metaComponent;
    }

    @SuppressWarnings("RedundantStreamOptionalCall") // Calling .sorted before .collect is intentional.
    private static Map<String, IntegrityMetaComponent> createIntegrityMetaComponents(
            final List<ConsumerRecord<String, AnalysisResult>> records
    ) {
        final var purlsSeen = new HashSet<String>();
        return records.stream()
                // Not all ecosystems support retrieval of integrity data.
                .filter(record -> record.value().hasIntegrityMeta())
                .map(record -> withEnrichedMdc(record, () -> createIntegrityMetaComponent(record)))
                // Sort by lastFetch such that later timestamps appear first.
                .sorted(Comparator.comparing(IntegrityMetaComponent::getLastFetch).reversed())
                // Only keep one (the latest) meta component for each PURL.
                .filter(metaComponent -> purlsSeen.add(metaComponent.getPurl()))
                .collect(Collectors.toMap(IntegrityMetaComponent::getPurl, Function.identity()));
    }

    private static IntegrityMetaComponent createIntegrityMetaComponent(final ConsumerRecord<String, AnalysisResult> record) {
        final AnalysisResult result = record.value();
        final IntegrityMeta integrityMetaResult = result.getIntegrityMeta();

        final var metaComponent = new IntegrityMetaComponent();
        metaComponent.setPurl(result.getComponent().getPurl());
        metaComponent.setRepositoryUrl(integrityMetaResult.getMetaSourceUrl());
        metaComponent.setMd5(trimToNull(integrityMetaResult.getMd5()));
        metaComponent.setSha1(trimToNull(integrityMetaResult.getSha1()));
        metaComponent.setSha256(trimToNull(integrityMetaResult.getSha256()));
        metaComponent.setSha512(trimToNull(integrityMetaResult.getSha512()));
        if (integrityMetaResult.hasCurrentVersionLastModified()) {
            metaComponent.setPublishedAt(new Date(Timestamps.toMillis(integrityMetaResult.getCurrentVersionLastModified())));
        }
        if (metaComponent.getMd5() != null
            || metaComponent.getSha1() != null
            || metaComponent.getSha256() != null
            || metaComponent.getSha512() != null) {
            metaComponent.setStatus(FetchStatus.PROCESSED);
        } else {
            metaComponent.setStatus(FetchStatus.NOT_AVAILABLE);
        }
        if (integrityMetaResult.getFetchedAt() != Timestamp.getDefaultInstance()) {
            metaComponent.setLastFetch(new Date(Timestamps.toMillis(integrityMetaResult.getFetchedAt())));
        } else {
            // For records sent by repository-meta-analyzer <=0.5.0.
            final var recordTimestamp = new Date(record.timestamp());
            LOGGER.warn("""
                    No fetched_at timestamp provided for integrity metadata, \
                    assuming record timestamp %s instead\
                    """.formatted(ISO_8601_EXTENDED_DATETIME_TIME_ZONE_FORMAT.format(recordTimestamp)));
            metaComponent.setLastFetch(recordTimestamp);
        }

        return metaComponent;
    }

    private static boolean isRecordValid(final ConsumerRecord<String, AnalysisResult> record) {
        final AnalysisResult result = record.value();
        if (!result.hasComponent()) {
            LOGGER.warn("Component is missing; Dropping");
            return false;
        }

        try {
            new PackageURL(result.getComponent().getPurl());
        } catch (MalformedPackageURLException e) {
            LOGGER.warn("Invalid PURL; Dropping", e);
            return false;
        }

        return true;
    }

}
