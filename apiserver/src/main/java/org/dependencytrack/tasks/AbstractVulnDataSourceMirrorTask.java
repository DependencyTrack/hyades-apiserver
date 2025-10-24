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
import com.google.protobuf.util.Timestamps;
import net.javacrumbs.shedlock.core.LockConfiguration;
import net.javacrumbs.shedlock.core.LockExtender;
import net.javacrumbs.shedlock.core.LockingTaskExecutor;
import org.cyclonedx.proto.v1_6.Bom;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.parser.dependencytrack.BovModelConverter;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.plugin.PluginManager;
import org.dependencytrack.plugin.api.datasource.vuln.VulnDataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;

import static org.datanucleus.PropertyNames.PROPERTY_PERSISTENCE_BY_REACHABILITY_AT_COMMIT;
import static org.dependencytrack.util.LockProvider.executeWithLock;
import static org.dependencytrack.util.LockProvider.isTaskLockToBeExtended;
import static org.dependencytrack.util.TaskUtil.getLockConfigForTask;

/**
 * @since 5.7.0
 */
abstract class AbstractVulnDataSourceMirrorTask implements Subscriber {

    private final PluginManager pluginManager;
    private final Class<? extends Event> eventClass;
    private final String vulnDataSourceExtensionName;
    protected final Vulnerability.Source source;
    protected final Logger logger;
    private LockConfiguration lockConfig;
    private Instant lockAcquiredAt;

    AbstractVulnDataSourceMirrorTask(
            final PluginManager pluginManager,
            final Class<? extends Event> eventClass,
            final String vulnDataSourceExtensionName,
            final Vulnerability.Source source) {
        this.pluginManager = pluginManager;
        this.eventClass = eventClass;
        this.vulnDataSourceExtensionName = vulnDataSourceExtensionName;
        this.source = source;
        this.logger = LoggerFactory.getLogger(this.getClass());
    }

    @Override
    public void inform(final Event e) {
        if (!eventClass.isAssignableFrom(e.getClass())) {
            return;
        }

        lockConfig = getLockConfigForTask(getClass());

        try {
            executeWithLock(
                    this.lockConfig,
                    (LockingTaskExecutor.Task) this::informLocked);
        } catch (Throwable ex) {
            logger.error("Failed to acquire lock or execute task", ex);
        }
    }

    private void informLocked() {
        lockAcquiredAt = Instant.now();

        try (final var dataSource = pluginManager.getExtension(VulnDataSource.class, vulnDataSourceExtensionName)) {
            if (dataSource == null) {
                return; // Likely disabled.
            }

            final var bovBatch = new ArrayList<Bom>(25);
            while (dataSource.hasNext()) {
                if (Thread.currentThread().isInterrupted()) {
                    logger.warn("Interrupted before all BOVs could be consumed");
                    break;
                }

                maybeExtendLock();

                final Bom bov = dataSource.next();
                if (!bov.getVulnerabilities(0).hasRejected()) {
                    bovBatch.add(bov);
                    if (bovBatch.size() == 25) {
                        processBatch(dataSource, bovBatch);
                        bovBatch.clear();
                    }
                } else {
                    // TODO: Store rejection / withdrawal timestamp instead,
                    //  and let analyzers / users decide how to deal with them.
                    //  Ignoring withdrawn vulnerabilities is legacy behavior.
                    logger.warn(
                            "Skipping vulnerability {} rejected at {}",
                            bov.getVulnerabilities(0).getId(),
                            Timestamps.toString(bov.getVulnerabilities(0).getRejected()));
                }
            }

            if (!bovBatch.isEmpty()) {
                maybeExtendLock();
                processBatch(dataSource, bovBatch);
                bovBatch.clear();
            }
        }
    }

    protected void processBatch(final VulnDataSource dataSource, final Collection<Bom> bovs) {
        logger.debug("Processing batch of {} BOVs", bovs.size());

        final var vulns = new ArrayList<Vulnerability>(bovs.size());
        final var vsListByVulnId = new HashMap<String, List<VulnerableSoftware>>(bovs.size());

        for (final Bom bov : bovs) {
            if (bov.getVulnerabilitiesCount() == 0) {
                logger.warn("BOV contains no vulnerabilities; Skipping");
                continue;
            }

            if (bov.getVulnerabilitiesCount() > 1) {
                logger.warn("BOV contains more than one vulnerability; Skipping");
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
                    logger.debug("Synchronizing vulnerability {}", vuln.getVulnId());
                    final Vulnerability persistentVuln = qm.synchronizeVulnerability(vuln, false);
                    final List<VulnerableSoftware> vsList = vsListByVulnId.get(persistentVuln.getVulnId());
                    qm.synchronizeVulnerableSoftware(persistentVuln, vsList, this.source);
                }
            });
        }

        for (final Bom bov : bovs) {
            dataSource.markProcessed(bov);
        }
    }

    private void maybeExtendLock() {
        final var lockAge = Duration.between(lockAcquiredAt, Instant.now());
        if (isTaskLockToBeExtended(lockAge.toMillis(), getClass())) {
            logger.warn("Extending lock by {}", lockConfig.getLockAtMostFor());
            LockExtender.extendActiveLock(lockConfig.getLockAtMostFor(), this.lockConfig.getLockAtLeastFor());
            lockAcquiredAt = Instant.now();
        }
    }

}
