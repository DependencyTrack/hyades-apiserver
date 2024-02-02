package org.dependencytrack.event.kafka.processor;

import org.eclipse.microprofile.health.HealthCheck;
import org.eclipse.microprofile.health.HealthCheckResponse;
import org.eclipse.microprofile.health.Liveness;

import static org.dependencytrack.event.kafka.processor.ProcessorInitializer.PROCESSOR_MANAGER;

@Liveness
public class ProcessorsHealthCheck implements HealthCheck {

    @Override
    public HealthCheckResponse call() {
        return PROCESSOR_MANAGER.probeHealth();
    }

}
