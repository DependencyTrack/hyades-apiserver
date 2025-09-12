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

import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import org.cyclonedx.proto.v1_6.Bom;
import org.dependencytrack.common.MdcScope;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.parser.dependencytrack.BovModelConverter;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.plugin.PluginManager;
import org.dependencytrack.plugin.api.ExtensionFactory;
import org.dependencytrack.plugin.api.datasource.vuln.VulnDataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.SequencedCollection;

import static org.datanucleus.PropertyNames.PROPERTY_PERSISTENCE_BY_REACHABILITY_AT_COMMIT;

/**
 * @since 5.7.0
 */
public final class VulnDataSourceMirrorTask implements Subscriber {

    private static final Logger LOGGER = LoggerFactory.getLogger(VulnDataSourceMirrorTask.class);

    private final PluginManager pluginManager;
    private final int batchSize;

    VulnDataSourceMirrorTask(final PluginManager pluginManager, final int batchSize) {
        this.pluginManager = pluginManager;
        this.batchSize = batchSize;
    }

    @SuppressWarnings("unused")
    public VulnDataSourceMirrorTask() {
        this(PluginManager.getInstance(), 100);
    }

    @Override
    public void inform(final Event event) {
        final SequencedCollection<ExtensionFactory<VulnDataSource>> dataSourceFactories =
                pluginManager.getFactories(VulnDataSource.class);

        for (final ExtensionFactory<VulnDataSource> dataSourceFactory : dataSourceFactories) {
            if (Thread.currentThread().isInterrupted()) {
                LOGGER.warn("Interrupted before all data sources could be mirrored");
                break;
            }

            LOGGER.info("Mirroring data source {}", dataSourceFactory.extensionName());

            try (final var ignoredMdcScope = new MdcScope(Map.of(
                    "dataSource", dataSourceFactory.extensionName()))) {
                try (final VulnDataSource dataSource = dataSourceFactory.create()) {
                    if (dataSource == null) {
                        continue;
                    }

                    // TODO: Fix this mess.
                    final Vulnerability.Source source = Vulnerability.Source.valueOf(
                            dataSourceFactory.extensionName().toUpperCase());

                    try {
                        LOGGER.info("Mirroring data source");
                        mirrorDataSource(dataSource, source);
                    } catch (RuntimeException e) {
                        LOGGER.error("Failed to mirror data source", e);
                    }
                }
            }
        }
    }

    private void mirrorDataSource(final VulnDataSource dataSource, final Vulnerability.Source source) {
        final var bovBatch = new ArrayList<Bom>(batchSize);

        while (dataSource.hasNext()) {
            if (Thread.currentThread().isInterrupted()) {
                LOGGER.warn("Interrupted before all BOVs could be consumed");
                break;
            }

            bovBatch.add(dataSource.next());
            if (bovBatch.size() == batchSize) {
                processBatch(dataSource, bovBatch, source);
                bovBatch.clear();
            }
        }

        if (!bovBatch.isEmpty()) {
            processBatch(dataSource, bovBatch, source);
            bovBatch.clear();
        }
    }

    private void processBatch(
            final VulnDataSource dataSource,
            final Collection<Bom> bovs,
            final Vulnerability.Source source) {
        LOGGER.info("Processing batch of {} BOVs", bovs.size());

        final var vulns = new ArrayList<Vulnerability>(bovs.size());
        final var vsListByVulnId = new HashMap<String, List<VulnerableSoftware>>(bovs.size());

        for (final Bom bov : bovs) {
            if (bov.getVulnerabilitiesCount() == 0) {
                LOGGER.warn("BOV contains no vulnerabilities; Skipping");
                continue;
            }

            if (bov.getVulnerabilitiesCount() > 1) {
                LOGGER.warn("BOV contains more than one vulnerability; Skipping");
                continue;
            }

            final Vulnerability vuln = BovModelConverter.convert(bov, bov.getVulnerabilities(0), true);
            final List<VulnerableSoftware> vsList = BovModelConverter.extractVulnerableSoftware(bov);

            vulns.add(vuln);
            vsListByVulnId.put(vuln.getVulnId(), vsList);
        }

        try (final var qm = new QueryManager()) {
            qm.getPersistenceManager().setProperty(PROPERTY_PERSISTENCE_BY_REACHABILITY_AT_COMMIT, "false");

            qm.runInTransaction(() -> {
                for (final Vulnerability vuln : vulns) {
                    LOGGER.debug("Synchronizing vulnerability {}", vuln.getVulnId());
                    final Vulnerability persistentVuln = qm.synchronizeVulnerability(vuln, false);
                    final List<VulnerableSoftware> vsList = vsListByVulnId.get(persistentVuln.getVulnId());
                    qm.synchronizeVulnerableSoftware(persistentVuln, vsList, source);
                }
            });
        }

        for (final Bom bov : bovs) {
            dataSource.markProcessed(bov);
        }
    }

}
