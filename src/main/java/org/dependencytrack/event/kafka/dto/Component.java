package org.dependencytrack.event.kafka.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import org.dependencytrack.model.Project;

import java.util.Objects;
import java.util.UUID;

/**
 * A DTO for communicating component data through Kafka.
 * <p>
 * It only includes data necessary for vulnerability analysis right now,
 * but may be extended to support more use cases in the future.
 * <p>
 * The only strictly required field for now is {@code project}, because it's currently
 * used as key for the Kafka event. May be subject to change though.
 * <p>
 * TODO: Investigate usage of schema registry for DTOs like this.
 *
 * @param uuid    {@link UUID} of the {@link Component}
 * @param group   Group of the {@link Component}
 * @param name    Name of the {@link Component}
 * @param version Version of the {@link Component}
 * @param purl    Package URL of the {@link Component}
 * @param cpe     CPE of the {@link Component}
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record Component(UUID uuid, String group, String name, String version, String purl, String cpe) {

    public Component(final UUID uuid, final String group, final String name, final String version,
                     final String purl, final String cpe) {
        this.uuid = uuid;
        this.group = group;
        this.name = name;
        this.version = version;
        this.purl = purl;
        this.cpe = cpe;
    }

    public Component(final org.dependencytrack.model.Component component) {
        this(component.getUuid(), component.getGroup(), component.getName(), component.getVersion(),
                component.getPurl() != null ? component.getPurl().canonicalize() : null, component.getCpe());
    }

}
