package org.dependencytrack.health;

import org.eclipse.microprofile.health.HealthCheckResponseBuilder;

public class HealthCheckResponseProvider implements org.eclipse.microprofile.health.spi.HealthCheckResponseProvider {

    @Override
    public HealthCheckResponseBuilder createResponseBuilder() {
        return new org.dependencytrack.health.HealthCheckResponseBuilder();
    }

}
