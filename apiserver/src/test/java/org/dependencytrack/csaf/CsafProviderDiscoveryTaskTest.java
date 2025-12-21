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

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.common.pagination.PageIterator;
import org.jdbi.v3.core.Handle;
import org.junit.Test;

import java.net.URI;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.openJdbiHandle;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

public class CsafProviderDiscoveryTaskTest extends PersistenceCapableTest {

    private Handle jdbiHandle;
    private CsafAggregatorDao aggregatorDao;
    private CsafProviderDao providerDao;

    @Override
    public void before() throws Exception {
        super.before();

        jdbiHandle = openJdbiHandle();
        aggregatorDao = jdbiHandle.attach(CsafAggregatorDao.class);
        providerDao = jdbiHandle.attach(CsafProviderDao.class);
    }

    @Override
    public void after() {
        if (jdbiHandle != null) {
            jdbiHandle.close();
        }

        super.after();
    }

    @Test
    public void shouldDiscoverAndCreateProviders() throws Exception {
        var aggregator = new CsafAggregator(
                URI.create("https://wid.cert-bund.de/.well-known/csaf-aggregator/aggregator.json"),
                URI.create("https://www.bsi.bund.de/"),
                "CSAF Lister des Bundesamts für Sicherheit in der Informationstechnik");
        aggregatorDao.create(aggregator);

        final var discoveredProvider = new CsafProvider(
                URI.create("https://wid.cert-bund.de/.well-known/csaf/provider-metadata.json"),
                URI.create("https://www.bsi.bund.de"),
                "Bundesamt für Sicherheit in der Informationstechnik");

        final var clientMock = mock(CsafClient.class);
        doReturn(Stream.of(discoveredProvider)).when(clientMock).discoverProviders(eq(aggregator));

        final var task = new CsafProviderDiscoveryTask(clientMock);
        task.inform(new CsafProviderDiscoveryEvent(aggregator));

        final List<CsafProvider> providers = PageIterator.stream(
                pageToken -> providerDao.list(
                        new ListCsafProvidersQuery()
                                .withPageToken(pageToken))).toList();

        final UUID aggregatorId = aggregator.getId();
        assertThat(providers).satisfiesExactly(provider -> {
            assertThat(provider.getNamespace()).asString().isEqualTo("https://www.bsi.bund.de");
            assertThat(provider.getName()).isEqualTo("Bundesamt für Sicherheit in der Informationstechnik");
            assertThat(provider.getUrl()).asString().isEqualTo("https://wid.cert-bund.de/.well-known/csaf/provider-metadata.json");
            assertThat(provider.isEnabled()).isFalse();
            assertThat(provider.getDiscoveredFrom()).isEqualTo(aggregatorId);
            assertThat(provider.getDiscoveredAt()).isNotNull();
            assertThat(provider.getLatestDocumentReleaseDate()).isNull();
            assertThat(provider.getCreatedAt()).isNotNull();
            assertThat(provider.getUpdatedAt()).isNull();
        });

        aggregator = aggregatorDao.getById(aggregator.getId());
        assertThat(aggregator).isNotNull();
        assertThat(aggregator.getLastDiscoveryAt()).isNotNull();
    }

}