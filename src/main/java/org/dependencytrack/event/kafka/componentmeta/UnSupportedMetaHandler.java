package org.dependencytrack.event.kafka.componentmeta;

import org.dependencytrack.event.ComponentRepositoryMetaAnalysisEvent;
import org.dependencytrack.event.kafka.KafkaEventDispatcher;
import org.dependencytrack.model.IntegrityMetaComponent;
import org.dependencytrack.persistence.QueryManager;
import org.hyades.proto.repometaanalysis.v1.FetchMeta;

public class UnSupportedMetaHandler extends AbstractMetaHandler {

    public UnSupportedMetaHandler(ComponentProjection componentProjection, QueryManager queryManager, KafkaEventDispatcher kafkaEventDispatcher, FetchMeta fetchMeta) {
        this.componentProjection = componentProjection;
        this.kafkaEventDispatcher = kafkaEventDispatcher;
        this.queryManager = queryManager;
        this.fetchMeta = fetchMeta;
    }

    @Override
    public IntegrityMetaComponent handle() {
        kafkaEventDispatcher.dispatchAsync(new ComponentRepositoryMetaAnalysisEvent(componentProjection.purlCoordinates(), componentProjection.internal(), fetchMeta));
        return null;
    }
}