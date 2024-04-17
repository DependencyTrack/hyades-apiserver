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
package org.dependencytrack.event.kafka.componentmeta;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.event.kafka.KafkaEventDispatcher;
import org.dependencytrack.event.kafka.KafkaTopics;
import org.dependencytrack.model.FetchStatus;
import org.dependencytrack.model.IntegrityMetaComponent;
import org.dependencytrack.proto.repometaanalysis.v1.FetchMeta;
import org.dependencytrack.util.PurlUtil;
import org.junit.Test;
import org.junit.jupiter.api.Assertions;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.util.KafkaTestUtil.deserializeValue;

public class SupportedMetaHandlerTest extends PersistenceCapableTest {

    @Test
    public void testHandleIntegrityComponentNotInDB() throws MalformedPackageURLException {
        Handler handler;
        UUID uuid = UUID.randomUUID();
        KafkaEventDispatcher kafkaEventDispatcher = new KafkaEventDispatcher();
        PackageURL packageUrl = new PackageURL("pkg:maven/org.http4s/blaze-core_2.12");
        ComponentProjection componentProjection = new ComponentProjection(uuid, PurlUtil.silentPurlCoordinatesOnly(packageUrl).toString(), false, packageUrl);
        IntegrityMetaComponent integrityMetaComponent = qm.getIntegrityMetaComponent(componentProjection.purl().toString());
        Assertions.assertNull(integrityMetaComponent);
        handler = HandlerFactory.createHandler(componentProjection, qm, kafkaEventDispatcher, FetchMeta.FETCH_META_INTEGRITY_DATA);
        IntegrityMetaComponent result = handler.handle();
        assertThat(kafkaMockProducer.history()).satisfiesExactly(
                record -> {
                    assertThat(record.topic()).isEqualTo(KafkaTopics.REPO_META_ANALYSIS_COMMAND.name());
                    final var command = deserializeValue(KafkaTopics.REPO_META_ANALYSIS_COMMAND, record);
                    assertThat(command.getComponent().getPurl()).isEqualTo("pkg:maven/org.http4s/blaze-core_2.12");
                    assertThat(command.getComponent().getUuid()).isEqualTo(uuid.toString());
                    assertThat(command.getComponent().getInternal()).isFalse();
                    assertThat(command.getFetchMeta()).isEqualTo(FetchMeta.FETCH_META_INTEGRITY_DATA);
                }

        );
        Assertions.assertEquals(FetchStatus.IN_PROGRESS, result.getStatus());
    }

    @Test
    public void testHandleIntegrityComponentInDBForMoreThanAnHour() throws MalformedPackageURLException {
        Handler handler;
        UUID uuid = UUID.randomUUID();
        KafkaEventDispatcher kafkaEventDispatcher = new KafkaEventDispatcher();
        PackageURL packageUrl = new PackageURL("pkg:maven/org.http4s/blaze-core_2.12");
        ComponentProjection componentProjection = new ComponentProjection(uuid, PurlUtil.silentPurlCoordinatesOnly(packageUrl).toString(), false, packageUrl);
        var integrityMeta = new IntegrityMetaComponent();
        integrityMeta.setPurl("pkg:maven/org.http4s/blaze-core_2.12");
        integrityMeta.setStatus(FetchStatus.IN_PROGRESS);
        integrityMeta.setLastFetch(Date.from(Instant.now().minus(2, ChronoUnit.HOURS)));
        qm.createIntegrityMetaComponent(integrityMeta);
        handler = HandlerFactory.createHandler(componentProjection, qm, kafkaEventDispatcher, FetchMeta.FETCH_META_INTEGRITY_DATA);
        IntegrityMetaComponent integrityMetaComponent = handler.handle();
        assertThat(kafkaMockProducer.history()).satisfiesExactly(
                record -> {
                    assertThat(record.topic()).isEqualTo(KafkaTopics.REPO_META_ANALYSIS_COMMAND.name());
                    final var command = deserializeValue(KafkaTopics.REPO_META_ANALYSIS_COMMAND, record);
                    assertThat(command.getComponent().getPurl()).isEqualTo("pkg:maven/org.http4s/blaze-core_2.12");
                    assertThat(command.getComponent().getUuid()).isEqualTo(uuid.toString());
                    assertThat(command.getComponent().getInternal()).isFalse();
                    assertThat(command.getFetchMeta()).isEqualTo(FetchMeta.FETCH_META_INTEGRITY_DATA);
                }

        );
        Assertions.assertEquals(FetchStatus.IN_PROGRESS, integrityMetaComponent.getStatus());
        assertThat(integrityMetaComponent.getLastFetch()).isAfter(Date.from(Instant.now().minus(2, ChronoUnit.MINUTES)));
    }

    @Test
    public void testHandleIntegrityWhenMetadataExists() throws MalformedPackageURLException {
        Handler handler;
        UUID uuid = UUID.randomUUID();
        KafkaEventDispatcher kafkaEventDispatcher = new KafkaEventDispatcher();
        PackageURL packageUrl = new PackageURL("pkg:maven/org.http4s/blaze-core_2.12");
        ComponentProjection componentProjection = new ComponentProjection(uuid, PurlUtil.silentPurlCoordinatesOnly(packageUrl).toString(), false, packageUrl);
        var integrityMeta = new IntegrityMetaComponent();
        integrityMeta.setPurl("pkg:maven/org.http4s/blaze-core_2.12");
        integrityMeta.setMd5("md5hash");
        integrityMeta.setStatus(FetchStatus.PROCESSED);
        integrityMeta.setLastFetch(Date.from(Instant.now().minus(2, ChronoUnit.HOURS)));
        qm.createIntegrityMetaComponent(integrityMeta);
        handler = HandlerFactory.createHandler(componentProjection, qm, kafkaEventDispatcher, FetchMeta.FETCH_META_INTEGRITY_DATA_AND_LATEST_VERSION);
        IntegrityMetaComponent integrityMetaComponent = handler.handle();
        assertThat(kafkaMockProducer.history()).satisfiesExactly(
                record -> {
                    assertThat(record.topic()).isEqualTo(KafkaTopics.REPO_META_ANALYSIS_COMMAND.name());
                    final var command = deserializeValue(KafkaTopics.REPO_META_ANALYSIS_COMMAND, record);
                    assertThat(command.getComponent().getPurl()).isEqualTo("pkg:maven/org.http4s/blaze-core_2.12");
                    assertThat(command.getComponent().getUuid()).isEqualTo(uuid.toString());
                    assertThat(command.getComponent().getInternal()).isFalse();
                    assertThat(command.getFetchMeta()).isEqualTo(FetchMeta.FETCH_META_LATEST_VERSION);
                }

        );
        Assertions.assertEquals(FetchStatus.PROCESSED, integrityMetaComponent.getStatus());
    }
}