package org.dependencytrack.event.kafka.componentmeta;

import org.dependencytrack.event.ComponentRepositoryMetaAnalysisEvent;
import org.dependencytrack.event.kafka.KafkaEventDispatcher;
import org.dependencytrack.model.FetchStatus;
import org.dependencytrack.model.IntegrityMetaComponent;
import org.dependencytrack.persistence.QueryManager;
import org.hyades.proto.repometaanalysis.v1.FetchMeta;

import java.time.Instant;
import java.util.Date;

import static org.dependencytrack.event.kafka.componentmeta.RepoMetaConstants.TIME_SPAN;

public class SupportedMetaHandler extends AbstractMetaHandler {

    public SupportedMetaHandler(ComponentProjection componentProjection, QueryManager queryManager, KafkaEventDispatcher kafkaEventDispatcher, boolean fetchLatestVersion) {
        this.componentProjection = componentProjection;
        this.kafkaEventDispatcher = kafkaEventDispatcher;
        this.queryManager = queryManager;
        this.fetchLatestVersion = fetchLatestVersion;
    }

    @Override
    public IntegrityMetaComponent handle() {
        FetchMeta fetchMeta;
        if (fetchLatestVersion) {
            fetchMeta = FetchMeta.FETCH_LATEST_VERSION;
        } else {
            fetchMeta = FetchMeta.FETCH_UNSPECIFIED;
        }
        IntegrityMetaComponent integrityMetaComponent = queryManager.getIntegrityMetaComponent(componentProjection.purl());
        if (integrityMetaComponent == null) {
            IntegrityMetaComponent integrityMetaComponent1 = queryManager.createIntegrityMetaComponent(createIntegrityMetaComponent(componentProjection.purl()));
            kafkaEventDispatcher.dispatchAsync(new ComponentRepositoryMetaAnalysisEvent(componentProjection.purlCoordinates(), componentProjection.internal(), FetchMeta.FETCH_INTEGRITY_DATA, fetchMeta));
            return integrityMetaComponent1;
        }
        if (integrityMetaComponent.getStatus() == null || (integrityMetaComponent.getStatus() == FetchStatus.IN_PROGRESS && Date.from(Instant.now()).getTime() - integrityMetaComponent.getLastFetch().getTime() > TIME_SPAN)) {
            integrityMetaComponent.setLastFetch(Date.from(Instant.now()));
            IntegrityMetaComponent integrityMetaComponent1 = queryManager.updateIntegrityMetaComponent(integrityMetaComponent);
            kafkaEventDispatcher.dispatchAsync(new ComponentRepositoryMetaAnalysisEvent(componentProjection.purlCoordinates(), componentProjection.internal(), FetchMeta.FETCH_INTEGRITY_DATA, fetchMeta));
            return integrityMetaComponent1;
        } else {
            kafkaEventDispatcher.dispatchAsync(new ComponentRepositoryMetaAnalysisEvent(componentProjection.purlCoordinates(), componentProjection.internal(), FetchMeta.FETCH_UNSPECIFIED, fetchMeta));
            return integrityMetaComponent;
        }
    }

}