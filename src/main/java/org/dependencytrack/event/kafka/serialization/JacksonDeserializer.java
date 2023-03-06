package org.dependencytrack.event.kafka.serialization;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.kafka.common.errors.SerializationException;
import org.apache.kafka.common.serialization.Deserializer;

import java.io.IOException;

public class JacksonDeserializer<T> implements Deserializer<T> {

    private final ObjectMapper objectMapper = new ObjectMapper().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    private final Class<T> clazz;

    public JacksonDeserializer(final Class<T> clazz) {
        this.clazz = clazz;
    }

    @Override
    public T deserialize(final String topic, byte[] data) {
        try {
            return objectMapper.readValue(data, clazz);
        } catch (IOException e) {
            throw new SerializationException(e);
        }
    }
}
