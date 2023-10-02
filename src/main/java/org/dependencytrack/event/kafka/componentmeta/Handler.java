package org.dependencytrack.event.kafka.componentmeta;

import org.dependencytrack.model.IntegrityMetaComponent;

public interface Handler {
    IntegrityMetaComponent handle();
}