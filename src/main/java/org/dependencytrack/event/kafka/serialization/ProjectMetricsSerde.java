package org.dependencytrack.event.kafka.serialization;

import org.apache.kafka.common.serialization.Deserializer;
import org.apache.kafka.common.serialization.Serde;
import org.apache.kafka.common.serialization.Serializer;
import org.dependencytrack.model.ProjectMetrics;


public class ProjectMetricsSerde implements Serde<ProjectMetrics> {

    private final Serializer<ProjectMetrics> serializer = new JacksonSerializer<>();
    private final Deserializer<ProjectMetrics> deserializer = new JacksonDeserializer<>(ProjectMetrics.class);

    @Override
    public Serializer<ProjectMetrics> serializer() {
        return serializer;
    }

    @Override
    public Deserializer<ProjectMetrics> deserializer() {
        return deserializer;
    }

}
