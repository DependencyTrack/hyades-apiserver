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

import io.github.resilience4j.core.IntervalFunction;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.common.pagination.PageIterator;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.dex.engine.api.TaskType;
import org.dependencytrack.dex.engine.api.TaskWorkerOptions;
import org.dependencytrack.dex.engine.api.WorkflowRunStatus;
import org.dependencytrack.dex.engine.api.request.CreateTaskQueueRequest;
import org.dependencytrack.dex.engine.api.request.CreateWorkflowRunRequest;
import org.dependencytrack.dex.testing.WorkflowTestExtension;
import org.dependencytrack.proto.internal.workflow.v1.DiscoverCsafProvidersArg;
import org.jdbi.v3.core.Handle;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.dex.api.payload.PayloadConverters.protoConverter;
import static org.dependencytrack.dex.api.payload.PayloadConverters.voidConverter;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.openJdbiHandle;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

class DiscoverCsafProvidersWorkflowTest extends PersistenceCapableTest {

    @RegisterExtension
    private final WorkflowTestExtension workflowTest =
            new WorkflowTestExtension(postgresContainer);

    private CsafClient csafClientMock;
    private Handle jdbiHandle;
    private CsafAggregatorDao aggregatorDao;
    private CsafProviderDao providerDao;

    @BeforeEach
    void beforeEach() {
        csafClientMock = mock(CsafClient.class);
        jdbiHandle = openJdbiHandle();
        aggregatorDao = jdbiHandle.attach(CsafAggregatorDao.class);
        providerDao = jdbiHandle.attach(CsafProviderDao.class);

        final DexEngine engine = workflowTest.getEngine();

        engine.registerWorkflow(
                new DiscoverCsafProvidersWorkflow(),
                protoConverter(DiscoverCsafProvidersArg.class),
                voidConverter(),
                Duration.ofSeconds(30));
        engine.registerActivity(
                new DiscoverCsafProvidersActivity(csafClientMock),
                protoConverter(DiscoverCsafProvidersArg.class),
                voidConverter(),
                Duration.ofSeconds(30));

        engine.createTaskQueue(new CreateTaskQueueRequest(TaskType.WORKFLOW, "default", 1));
        engine.createTaskQueue(new CreateTaskQueueRequest(TaskType.ACTIVITY, "default", 1));

        engine.registerTaskWorker(
                new TaskWorkerOptions(TaskType.WORKFLOW, "workflow-worker", "default", 1)
                        .withMinPollInterval(Duration.ofMillis(25))
                        .withPollBackoffFunction(IntervalFunction.of(25)));
        engine.registerTaskWorker(
                new TaskWorkerOptions(TaskType.ACTIVITY, "activity-worker-default", "default", 1)
                        .withMinPollInterval(Duration.ofMillis(25))
                        .withPollBackoffFunction(IntervalFunction.of(25)));

        engine.start();
    }

    @AfterEach
    void afterEach() {
        if (jdbiHandle != null) {
            jdbiHandle.close();
        }
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

        doReturn(Stream.of(discoveredProvider)).when(csafClientMock).discoverProviders(eq(aggregator));

        final UUID runId = workflowTest.getEngine().createRun(
                new CreateWorkflowRunRequest<>(DiscoverCsafProvidersWorkflow.class)
                        .withArgument(DiscoverCsafProvidersArg.newBuilder()
                                .setAggregatorId(aggregator.getId().toString())
                                .build()));
        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

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