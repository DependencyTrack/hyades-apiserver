package org.dependencytrack.event.kafka.serialization;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.apache.kafka.common.errors.SerializationException;
import org.apache.kafka.common.serialization.Serializer;

import java.util.Optional;


public class JacksonSerializer<T> implements Serializer<T> {

    private final ObjectMapper objectMapper;

    public JacksonSerializer() {
        this(null);
    }

    public JacksonSerializer(final ObjectMapper objectMapper) {
        this.objectMapper = Optional.ofNullable(objectMapper)
                .orElseGet(() -> new ObjectMapper().registerModule(new JavaTimeModule()));
    }

    @Override
    public byte[] serialize(final String topic, final T data) {
        try {
            if (data == null) {
                return null;
            }
            return objectMapper.writeValueAsBytes(data);
        } catch (JsonProcessingException e) {
            throw new SerializationException(e);
        }
    }

}
