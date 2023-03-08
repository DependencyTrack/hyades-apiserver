package org.dependencytrack.event.kafka.serialization;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.apache.kafka.common.errors.SerializationException;
import org.apache.kafka.common.serialization.Deserializer;

import java.io.IOException;
import java.util.Optional;

public class JacksonDeserializer<T> implements Deserializer<T> {

    private final ObjectMapper objectMapper;
    private final Class<T> clazz;

    public JacksonDeserializer(final Class<T> clazz) {
        this(clazz, null);
    }

    public JacksonDeserializer(final Class<T> clazz, final ObjectMapper objectMapper) {
        this.clazz = clazz;
        this.objectMapper = Optional.ofNullable(objectMapper)
                .orElseGet(() -> new ObjectMapper().registerModule(new JavaTimeModule())).configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
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
