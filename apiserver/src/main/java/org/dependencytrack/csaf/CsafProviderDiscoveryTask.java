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
package org.dependencytrack.csaf;

import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import java.time.Instant;
import java.util.List;
import java.util.concurrent.ExecutionException;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;

/**
 * TODO: Refactor to dex workflow + activity once dex engine is integrated.
 *   * Use workflow instance ID to ensure only one workflow run per aggregator can exist.
 *   * Use same concurrency key across all aggregators to serialize their execution.
 *
 * @since 5.7.0
 */
public class CsafProviderDiscoveryTask implements Subscriber {

    private static final Logger LOGGER = LoggerFactory.getLogger(CsafProviderDiscoveryTask.class);

    private final CsafClient csafClient;

    CsafProviderDiscoveryTask(CsafClient csafClient) {
        this.csafClient = csafClient;
    }

    @SuppressWarnings("unused") // Used by event system.
    public CsafProviderDiscoveryTask() {
        this(new CsafClient());
    }

    @Override
    public void inform(Event e) {
        if (!(e instanceof final CsafProviderDiscoveryEvent event)) {
            return;
        }

        final CsafAggregator aggregator = event.getAggregator();

        try (var ignored = MDC.putCloseable("csafAggregator", aggregator.getNamespace().toString())) {
            LOGGER.info("Discovering providers");

            final List<CsafProvider> discoveredProviders;
            try {
                discoveredProviders =
                        csafClient.discoverProviders(aggregator)
                                .peek(provider -> {
                                    provider.setEnabled(false);
                                    provider.setDiscoveredFrom(aggregator.getId());
                                    provider.setDiscoveredAt(Instant.now());
                                })
                                .toList();
            } catch (ExecutionException | RuntimeException ex) {
                throw new IllegalStateException("Failed to discover providers", ex);
            } catch (InterruptedException ex) {
                LOGGER.warn("Interrupted while discovering providers", ex);
                Thread.currentThread().interrupt();
                return;
            }

            if (discoveredProviders.isEmpty()) {
                LOGGER.info("No providers discovered");
                return;
            }

            LOGGER.info("Discovered {} providers", discoveredProviders.size());

            final List<CsafProvider> createdProviders = inJdbiTransaction(
                    handle -> handle.attach(CsafProviderDao.class).createAll(discoveredProviders));
            for (final CsafProvider createdProvider : createdProviders) {
                LOGGER.info("Created provider {}", createdProvider.getNamespace());
            }

            useJdbiTransaction(handle -> handle.attach(CsafAggregatorDao.class)
                    .updateLastDiscoveryAtById(aggregator.getId(), Instant.now()));
        }
    }

}
