package org.dependencytrack.event.kafka.processor;

import io.confluent.parallelconsumer.ParallelEoSStreamProcessor;
import io.confluent.parallelconsumer.ParallelStreamProcessor;
import org.eclipse.microprofile.health.HealthCheck;
import org.eclipse.microprofile.health.HealthCheckResponse;
import org.eclipse.microprofile.health.HealthCheckResponseBuilder;
import org.eclipse.microprofile.health.Liveness;

import java.util.Map;

@Liveness
public class KafkaProcessorHealthCheck implements HealthCheck {

    @Override
    public HealthCheckResponse call() {
        final KafkaProcessorManager processorManager = KafkaProcessorInitializer.processorManager();
        if (processorManager == null) {
            return HealthCheckResponse.builder().down().build();
        }

        boolean isUp = true;
        final HealthCheckResponseBuilder responseBuilder = HealthCheckResponse.named("kafka-processor");
        for (final Map.Entry<String, ParallelStreamProcessor<byte[], byte[]>> processorByName : processorManager.processors().entrySet()) {
            final String processorName = processorByName.getKey();
            final ParallelStreamProcessor<?, ?> processor = processorByName.getValue();

            final boolean isProcessorUp = !processor.isClosedOrFailed();
            responseBuilder.withData(processorName, isProcessorUp
                    ? HealthCheckResponse.Status.UP.name()
                    : HealthCheckResponse.Status.DOWN.name());

            if (!isProcessorUp
                    && processor instanceof final ParallelEoSStreamProcessor<?, ?> concreteProcessor
                    && concreteProcessor.getFailureCause() != null) {
                isUp = false;
                responseBuilder.withData("%s_failure_cause".formatted(processorName),
                        concreteProcessor.getFailureCause().getMessage());
            }
        }

        return responseBuilder.status(isUp).build();
    }

}
