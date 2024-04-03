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

import org.dependencytrack.event.kafka.processor.exception.ProcessingException;
import org.dependencytrack.proto.mirror.v1.EpssItem;
import org.junit.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

public class EpssMirrorProcessorTest extends AbstractProcessorTest {

    @Test
    public void testProcessEpssRecord() throws ProcessingException {
        final var epssRecord = EpssItem.newBuilder()
                .setCve("CVE-333").setEpss(2.3).setPercentile(5.6).build();
        final var processor = new EpssMirrorProcessor();
        processor.process(List.of(aConsumerRecord("CVE-333", epssRecord).build()));
        final var epss = qm.getEpssByCveId("CVE-333");
        assertThat(epss).isNotNull();
        assertThat(epss.getScore()).isEqualByComparingTo("2.3");
        assertThat(epss.getPercentile()).isEqualByComparingTo("5.6");
    }

    @Test
    public void testProcessNullEpssRecord() throws ProcessingException {
        final var processor = new EpssMirrorProcessor();
        processor.process(List.of(aConsumerRecord("CVE-333", EpssItem.newBuilder().build()).build()));
        final var epss = qm.getEpssByCveId("CVE-333");
        assertThat(epss).isNull();
    }
}
