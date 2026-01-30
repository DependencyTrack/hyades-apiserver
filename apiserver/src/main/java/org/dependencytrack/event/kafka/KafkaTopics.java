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

import alpine.Config;
import org.apache.kafka.common.serialization.Serde;
import org.apache.kafka.common.serialization.Serdes;
import org.dependencytrack.common.ConfigKey;
import org.dependencytrack.event.kafka.serialization.KafkaProtobufSerde;
import org.dependencytrack.proto.repometaanalysis.v1.AnalysisCommand;
import org.dependencytrack.proto.repometaanalysis.v1.AnalysisResult;
import org.dependencytrack.proto.vulnanalysis.v1.ScanCommand;
import org.dependencytrack.proto.vulnanalysis.v1.ScanKey;
import org.dependencytrack.proto.vulnanalysis.v1.ScanResult;

public final class KafkaTopics {

    public static final Topic<String, AnalysisCommand> REPO_META_ANALYSIS_COMMAND;
    public static final Topic<String, AnalysisResult> REPO_META_ANALYSIS_RESULT;
    public static final Topic<ScanKey, ScanCommand> VULN_ANALYSIS_COMMAND;
    public static final Topic<ScanKey, ScanResult> VULN_ANALYSIS_RESULT;
    public static final Topic<String, ScanResult> VULN_ANALYSIS_RESULT_PROCESSED;

    static {
        REPO_META_ANALYSIS_COMMAND = new Topic<>("dtrack.repo-meta-analysis.component", Serdes.String(), new KafkaProtobufSerde<>(AnalysisCommand.parser()));
        REPO_META_ANALYSIS_RESULT = new Topic<>("dtrack.repo-meta-analysis.result", Serdes.String(), new KafkaProtobufSerde<>(AnalysisResult.parser()));
        VULN_ANALYSIS_COMMAND = new Topic<>("dtrack.vuln-analysis.component", new KafkaProtobufSerde<>(ScanKey.parser()), new KafkaProtobufSerde<>(ScanCommand.parser()));
        VULN_ANALYSIS_RESULT = new Topic<>("dtrack.vuln-analysis.result", new KafkaProtobufSerde<>(ScanKey.parser()), new KafkaProtobufSerde<>(ScanResult.parser()));
        VULN_ANALYSIS_RESULT_PROCESSED = new Topic<>("dtrack.vuln-analysis.result.processed", Serdes.String(), new KafkaProtobufSerde<>(ScanResult.parser()));
    }

    public record Topic<K, V>(String name, Serde<K> keySerde, Serde<V> valueSerde) {

        @Override
        public String name() {
            return Config.getInstance().getProperty(ConfigKey.DT_KAFKA_TOPIC_PREFIX) + name;
        }

    }

}
