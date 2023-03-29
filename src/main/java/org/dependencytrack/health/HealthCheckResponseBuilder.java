package org.dependencytrack.health;

import org.eclipse.microprofile.health.HealthCheckResponse;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

import static java.util.function.Predicate.not;

/**
 * Implementation of the MicroProfile {@link org.eclipse.microprofile.health.HealthCheckResponseBuilder} SPI.
 * <p>
 * This code has been copied from the SmallRye Health project.
 *
 * @see <a href="https://github.com/smallrye/smallrye-health/blob/main/implementation/src/main/java/io/smallrye/health/ResponseBuilder.java">SmallRye ResponseBuilder</a>
 */
public class HealthCheckResponseBuilder extends org.eclipse.microprofile.health.HealthCheckResponseBuilder {

    private String name;

    private HealthCheckResponse.Status status = HealthCheckResponse.Status.DOWN;

    private final Map<String, Object> data = new LinkedHashMap<>();

    @Override
    public HealthCheckResponseBuilder name(String name) {
        this.name = name;
        return this;
    }

    @Override
    public HealthCheckResponseBuilder withData(String key, String value) {
        this.data.put(key, value);
        return this;
    }

    @Override
    public HealthCheckResponseBuilder withData(String key, long value) {
        this.data.put(key, value);
        return this;
    }

    @Override
    public HealthCheckResponseBuilder withData(String key, boolean value) {
        this.data.put(key, value);
        return this;
    }

    @Override
    public HealthCheckResponseBuilder up() {
        this.status = HealthCheckResponse.Status.UP;
        return this;
    }

    @Override
    public HealthCheckResponseBuilder down() {
        this.status = HealthCheckResponse.Status.DOWN;
        return this;
    }

    @Override
    public HealthCheckResponseBuilder status(boolean up) {
        if (up) {
            return up();
        }

        return down();
    }

    @Override
    public HealthCheckResponse build() {
        if (null == this.name || this.name.trim().length() == 0) {
            throw new IllegalArgumentException("Health Check contains an invalid name. Can not be null or empty.");
        }

        return new HealthCheckResponse(this.name, this.status, Optional.of(data).filter(not(Map::isEmpty)));
    }

}
