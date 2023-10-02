package org.dependencytrack.event.kafka.componentmeta;

import org.dependencytrack.event.ComponentRepositoryMetaAnalysisEvent;
import org.dependencytrack.event.kafka.KafkaEventDispatcher;
import org.dependencytrack.model.IntegrityMetaComponent;
import org.dependencytrack.persistence.QueryManager;

public class UnSupportedMetaHandler extends AbstractMetaHandler {

    public UnSupportedMetaHandler(ComponentProjection componentProjection, QueryManager queryManager, KafkaEventDispatcher kafkaEventDispatcher,boolean fetchLatestVersion) {
        this.componentProjection = componentProjection;
        this.kafkaEventDispatcher = kafkaEventDispatcher;
        this.queryManager = queryManager;
        this.fetchLatestVersion = fetchLatestVersion;
    }

    @Override
    public IntegrityMetaComponent handle() {
        KafkaEventDispatcher kafkaEventDispatcher = new KafkaEventDispatcher();
        kafkaEventDispatcher.dispatchAsync(new ComponentRepositoryMetaAnalysisEvent(componentProjection.purlCoordinates(), componentProjection.internal(), false, fetchLatestVersion));
        return null;
    }
}
