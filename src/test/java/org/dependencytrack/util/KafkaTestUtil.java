package org.dependencytrack.util;

import com.google.protobuf.Struct;
import com.google.protobuf.util.JsonFormat;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.cyclonedx.proto.v1_4.Bom;
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
