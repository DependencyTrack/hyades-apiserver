package org.dependencytrack.event.kafka.componentmeta;

import org.dependencytrack.event.ComponentRepositoryMetaAnalysisEvent;
import org.dependencytrack.event.kafka.KafkaEventDispatcher;
import org.dependencytrack.model.IntegrityMetaComponent;
import org.dependencytrack.persistence.QueryManager;
import org.hyades.proto.repometaanalysis.v1.FetchMeta;

public class UnSupportedMetaHandler extends AbstractMetaHandler {

    public UnSupportedMetaHandler(ComponentProjection componentProjection, QueryManager queryManager, KafkaEventDispatcher kafkaEventDispatcher, boolean fetchLatestVersion) {
        this.componentProjection = componentProjection;
        this.kafkaEventDispatcher = kafkaEventDispatcher;
        this.queryManager = queryManager;
        this.fetchLatestVersion = fetchLatestVersion;
    }

    @Override
    public IntegrityMetaComponent handle() {
        if(fetchLatestVersion){
            kafkaEventDispatcher.dispatchAsync(new ComponentRepositoryMetaAnalysisEvent(componentProjection.purlCoordinates(), componentProjection.internal(), FetchMeta.FETCH_META_UNSPECIFIED, FetchMeta.FETCH_META_LATEST_VERSION));
        } else{
            kafkaEventDispatcher.dispatchAsync(new ComponentRepositoryMetaAnalysisEvent(componentProjection.purlCoordinates(), componentProjection.internal(), FetchMeta.FETCH_META_UNSPECIFIED, FetchMeta.FETCH_META_UNSPECIFIED));
        }
        return null;
    }
}