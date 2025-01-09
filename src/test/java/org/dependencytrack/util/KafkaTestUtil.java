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
package org.dependencytrack.util;

import com.google.protobuf.util.JsonFormat;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.cyclonedx.proto.v1_6.Bom;
import org.dependencytrack.event.kafka.KafkaTopics;

import java.io.IOException;

public final class KafkaTestUtil {

    private KafkaTestUtil() {
    }

    public static <K> K deserializeKey(final KafkaTopics.Topic<K, ?> topic, final ProducerRecord<byte[], ?> record) {
        return topic.keySerde().deserializer().deserialize(topic.name(), record.key());
    }

    public static <V> V deserializeValue(final KafkaTopics.Topic<?, V> topic, final ProducerRecord<?, byte[]> record) {
        return topic.valueSerde().deserializer().deserialize(topic.name(), record.value());
    }

    public static Bom generateBomFromJson(String json) throws IOException {
        Bom.Builder bomBuilder = Bom.newBuilder();
        JsonFormat.parser().ignoringUnknownFields().merge(json, bomBuilder);
        return bomBuilder.build();
    }

}
