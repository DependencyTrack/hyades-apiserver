package org.dependencytrack.event.kafka.serialization;

import org.apache.kafka.common.serialization.Deserializer;
import org.apache.kafka.common.serialization.Serde;
import org.apache.kafka.common.serialization.Serializer;
import org.dependencytrack.model.DependencyMetrics;


public class DependencyMetricsSerde implements Serde<DependencyMetrics> {

    private final Serializer<DependencyMetrics> serializer = new JacksonSerializer<>();
    private final Deserializer<DependencyMetrics> deserializer = new JacksonDeserializer<>(DependencyMetrics.class);

    @Override
    public Serializer<DependencyMetrics> serializer() {
        return serializer;
    }

    @Override
    public Deserializer<DependencyMetrics> deserializer() {
        return deserializer;
    }

}
