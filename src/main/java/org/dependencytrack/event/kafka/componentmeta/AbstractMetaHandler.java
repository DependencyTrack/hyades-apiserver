package org.dependencytrack.event.kafka.componentmeta;

import org.dependencytrack.event.kafka.KafkaEventDispatcher;
import org.dependencytrack.model.FetchStatus;
import org.dependencytrack.model.IntegrityMetaComponent;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.proto.repometaanalysis.v1.FetchMeta;

import java.time.Instant;
import java.util.Date;

public abstract class AbstractMetaHandler implements Handler {

    ComponentProjection componentProjection;
    QueryManager queryManager;
    KafkaEventDispatcher kafkaEventDispatcher;
    FetchMeta fetchMeta;


    public static IntegrityMetaComponent createIntegrityMetaComponent(String purl) {
        IntegrityMetaComponent integrityMetaComponent = new IntegrityMetaComponent();
        integrityMetaComponent.setStatus(FetchStatus.IN_PROGRESS);
        integrityMetaComponent.setPurl(purl);
        integrityMetaComponent.setLastFetch(Date.from(Instant.now()));
        return integrityMetaComponent;
    }

}