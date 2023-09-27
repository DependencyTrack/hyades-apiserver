package org.dependencytrack.event.kafka.componentmeta;

import org.dependencytrack.event.kafka.KafkaEventDispatcher;
import org.dependencytrack.model.FetchStatus;
import org.dependencytrack.model.IntegrityMetaComponent;
import org.dependencytrack.persistence.QueryManager;

import java.time.Instant;
import java.util.Date;

public abstract class AbstractMetaHandler implements Handler {

    ComponentProjection componentProjection;
    QueryManager queryManager;
    KafkaEventDispatcher kafkaEventDispatcher;
    boolean fetchLatestVersion;


    public static IntegrityMetaComponent createIntegrityMetaComponent(String purl) {
        IntegrityMetaComponent integrityMetaComponent1 = new IntegrityMetaComponent();
        integrityMetaComponent1.setStatus(FetchStatus.IN_PROGRESS);
        integrityMetaComponent1.setPurl(purl);
        integrityMetaComponent1.setLastFetch(Date.from(Instant.now()));
        return integrityMetaComponent1;
    }

}
