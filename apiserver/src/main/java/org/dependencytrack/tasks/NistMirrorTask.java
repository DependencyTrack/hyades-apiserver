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
import alpine.event.framework.LoggableSubscriber;
import net.javacrumbs.shedlock.core.LockConfiguration;
import net.javacrumbs.shedlock.core.LockExtender;
import net.javacrumbs.shedlock.core.LockingTaskExecutor;
import org.cyclonedx.proto.v1_6.Bom;
import org.dependencytrack.event.NistMirrorEvent;
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
 * Task for mirroring vulnerability data from the national vulnerability database (NVD).
 * <p>
 * The logic in this task is not NVD-specific and should eventually be used for all
 * vulnerability data sources.
 */
public class NistMirrorTask implements LoggableSubscriber {

    private static final Logger LOGGER = LoggerFactory.getLogger(NistMirrorTask.class);

    private final PluginManager pluginManager;
    private LockConfiguration lockConfig;
    private Instant lockAcquiredAt;

    NistMirrorTask(PluginManager pluginManager) {
        this.pluginManager = pluginManager;
    }

    @SuppressWarnings("unused")
    public NistMirrorTask() {
        this(PluginManager.getInstance());
    }

    public void inform(final Event e) {
        if (!(e instanceof NistMirrorEvent)) {
            return;
        }

        lockConfig = getLockConfigForTask(getClass());

        try {
            executeWithLock(
                    this.lockConfig,
                    (LockingTaskExecutor.Task) this::informLocked);
        } catch (Throwable ex) {
            LOGGER.error("Failed to acquire lock or execute task", ex);
        }
    }

    private void informLocked() {
        lockAcquiredAt = Instant.now();

        try (final var dataSource = pluginManager.getExtension(VulnDataSource.class, "nvd")) {
            if (dataSource == null) {
                return; // Likely disabled.
            }

            final var bovBatch = new ArrayList<Bom>(25);
            while (dataSource.hasNext()) {
                if (Thread.currentThread().isInterrupted()) {
                    LOGGER.warn("Interrupted before all BOVs could be consumed");
                    break;
                }

                maybeExtendLock();

                bovBatch.add(dataSource.next());
                if (bovBatch.size() == 25) {
                    processBatch(dataSource, bovBatch);
                    bovBatch.clear();
                }
            }

            if (!bovBatch.isEmpty()) {
                maybeExtendLock();
                processBatch(dataSource, bovBatch);
                bovBatch.clear();
            }
        }
    }

    private void processBatch(final VulnDataSource dataSource, final Collection<Bom> bovs) {
        LOGGER.debug("Processing batch of {} BOVs", bovs.size());

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
                    qm.synchronizeVulnerableSoftware(persistentVuln, vsList, Vulnerability.Source.NVD);
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
            LOGGER.warn("Extending lock by {}", lockConfig.getLockAtMostFor());
            LockExtender.extendActiveLock(lockConfig.getLockAtMostFor(), this.lockConfig.getLockAtLeastFor());
            lockAcquiredAt = Instant.now();
        }
    }

}