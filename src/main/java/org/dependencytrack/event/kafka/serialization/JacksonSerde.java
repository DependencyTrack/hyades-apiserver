package org.dependencytrack.event.kafka.serialization;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.kafka.common.serialization.Deserializer;
import org.apache.kafka.common.serialization.Serde;
import org.apache.kafka.common.serialization.Serializer;

public class JacksonSerde<T> implements Serde<T> {

    private final JacksonSerializer<T> serializer;
    private final JacksonDeserializer<T> deserializer;

    public JacksonSerde(final Class<T> clazz) {
        this(clazz, null);
    }

    public JacksonSerde(final Class<T> clazz, final ObjectMapper objectMapper) {
        this.serializer = new JacksonSerializer<>(objectMapper);
        this.deserializer = new JacksonDeserializer<>(clazz, objectMapper);
    }

    @Override
    public Serializer<T> serializer() {
        return serializer;
    }

    @Override
    public Deserializer<T> deserializer() {
        return deserializer;
    }

}
