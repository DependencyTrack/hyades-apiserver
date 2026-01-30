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

import org.dependencytrack.dex.api.Activity;
import org.dependencytrack.dex.api.ActivityContext;
import org.dependencytrack.dex.api.ActivitySpec;
import org.dependencytrack.dex.api.failure.TerminalApplicationFailureException;
import org.dependencytrack.proto.internal.workflow.v1.DiscoverCsafProvidersArg;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

/**
 * @since 5.7.0
 */
@ActivitySpec(name = "discover-csaf-providers")
public final class DiscoverCsafProvidersActivity implements Activity<DiscoverCsafProvidersArg, Void> {

    private static final Logger LOGGER = LoggerFactory.getLogger(DiscoverCsafProvidersActivity.class);

    private final CsafClient csafClient;

    DiscoverCsafProvidersActivity(CsafClient csafClient) {
        this.csafClient = csafClient;
    }

    public DiscoverCsafProvidersActivity() {
        this(new CsafClient());
    }

    @Override
    public @Nullable Void execute(
            ActivityContext ctx,
            @Nullable DiscoverCsafProvidersArg arg) throws Exception {
        if (arg == null) {
            throw new TerminalApplicationFailureException("No argument provided");
        }

        final CsafAggregator aggregator = withJdbiHandle(
                handle -> handle.attach(CsafAggregatorDao.class).getById(UUID.fromString(arg.getAggregatorId())));
        if (aggregator == null) {
            throw new TerminalApplicationFailureException(
                    "Aggregator with ID %s does not exist".formatted(arg.getAggregatorId()));
        }

        try (var ignored = MDC.putCloseable("csafAggregator", aggregator.getNamespace().toString())) {
            LOGGER.info("Discovering providers");

            final List<CsafProvider> discoveredProviders =
                    csafClient.discoverProviders(aggregator)
                            .peek(provider -> {
                                provider.setEnabled(false);
                                provider.setDiscoveredFrom(aggregator.getId());
                                provider.setDiscoveredAt(Instant.now());
                            })
                            .toList();

            if (discoveredProviders.isEmpty()) {
                LOGGER.info("No providers discovered");
                return null;
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

        return null;
    }

}
