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
import org.dependencytrack.model.IntegrityMetaComponent;
import org.dependencytrack.proto.repometaanalysis.v1.FetchMeta;
import org.dependencytrack.util.PurlUtil;
import org.junit.Test;
import org.junit.jupiter.api.Assertions;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.util.KafkaTestUtil.deserializeValue;

public class UnSupportedMetaHandlerTest extends PersistenceCapableTest {

    @Test
    public void testHandleComponentInDb() throws MalformedPackageURLException {
        Handler handler;
        KafkaEventDispatcher kafkaEventDispatcher = new KafkaEventDispatcher();
        PackageURL packageUrl = new PackageURL("pkg:golang/foo/bar@baz?ping=pong#1/2/3");
        ComponentProjection componentProjection = new ComponentProjection(null, PurlUtil.silentPurlCoordinatesOnly(packageUrl).toString(), false, packageUrl);
        IntegrityMetaComponent integrityMetaComponent = qm.getIntegrityMetaComponent(componentProjection.purl().toString());
        Assertions.assertNull(integrityMetaComponent);
        handler = HandlerFactory.createHandler(componentProjection, qm, kafkaEventDispatcher, FetchMeta.FETCH_META_LATEST_VERSION);
        handler.handle();
        assertThat(kafkaMockProducer.history()).satisfiesExactly(
                record -> {
                    assertThat(record.topic()).isEqualTo(KafkaTopics.REPO_META_ANALYSIS_COMMAND.name());
                    final var command = deserializeValue(KafkaTopics.REPO_META_ANALYSIS_COMMAND, record);
                    assertThat(command.getComponent().getPurl()).isEqualTo("pkg:golang/foo/bar@baz");
                    assertThat(command.getComponent().getInternal()).isFalse();
                    assertThat(command.getFetchMeta()).isEqualTo(FetchMeta.FETCH_META_LATEST_VERSION);
                }

        );
        Assertions.assertNull(integrityMetaComponent);
    }
}