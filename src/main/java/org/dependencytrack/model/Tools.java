package org.dependencytrack.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonView;

import java.util.List;

@JsonInclude(JsonInclude.Include.NON_EMPTY)
public record Tools(
        @JsonView(JsonViews.MetadataTools.class) List<Component> components,
        @JsonView(JsonViews.MetadataTools.class) List<ServiceComponent> services) {
}
