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
package org.dependencytrack.event.kafka;

import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.EnvironmentVariables;

import static org.assertj.core.api.Assertions.assertThat;

public class KafkaTopicsTest {

    @Rule
    public final EnvironmentVariables environmentVariables = new EnvironmentVariables();

    @Test
    public void testTopicNameWithPrefix() {
        environmentVariables.set("DT_KAFKA_TOPIC_PREFIX", "foo-bar.baz.");
        assertThat(KafkaTopics.VULN_ANALYSIS_RESULT.name()).isEqualTo("foo-bar.baz.dtrack.vuln-analysis.result");
    }

    @Test
    public void testTopicNameWithoutPrefix() {
        assertThat(KafkaTopics.VULN_ANALYSIS_RESULT.name()).isEqualTo("dtrack.vuln-analysis.result");
    }

}