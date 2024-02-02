package org.dependencytrack.health;

import org.apache.kafka.streams.KafkaStreams;
import org.dependencytrack.event.kafka.streams.KafkaStreamsInitializer;
import org.eclipse.microprofile.health.HealthCheck;
import org.eclipse.microprofile.health.HealthCheckResponse;
import org.eclipse.microprofile.health.Liveness;

/**
 * A {@link HealthCheck} for Kafka Streams.
 * <p>
 * This code has been copied and slightly modified from Quarkus' Kafka Streams extension.
 *
 * @see <a href="https://github.com/quarkusio/quarkus/blob/2.16.5.Final/extensions/kafka-streams/runtime/src/main/java/io/quarkus/kafka/streams/runtime/health/KafkaStreamsStateHealthCheck.java">Quarkus Kafka Streams Health Check</a>
 */
@Liveness
class KafkaStreamsHealthCheck implements HealthCheck {

    @Override
    public HealthCheckResponse call() {
        final var responseBuilder = HealthCheckResponse.named("kafka-streams");

        final KafkaStreams kafkaStreams = KafkaStreamsInitializer.getKafkaStreams();
        if (kafkaStreams == null) {
            return responseBuilder.down().build();
        }

        try {
            final KafkaStreams.State state = kafkaStreams.state();
            responseBuilder.status(state.isRunningOrRebalancing())
                    .withData("state", state.name());
        } catch (Exception e) {
            responseBuilder.down()
                    .withData("exception_message", e.getMessage());
        }

        return responseBuilder.build();
    }

}
