package org.dependencytrack.util;

import org.apache.kafka.clients.producer.ProducerRecord;
import org.dependencytrack.event.kafka.KafkaTopics;

public final class KafkaTestUtil {

    private KafkaTestUtil() {
    }

    public static <V> V deserializeValue(final KafkaTopics.Topic<?, V> topic, final ProducerRecord<?, byte[]> record) {
        return topic.valueSerde().deserializer().deserialize(topic.name(), record.value());
    }

}
