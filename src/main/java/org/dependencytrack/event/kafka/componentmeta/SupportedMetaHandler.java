package org.dependencytrack.event.kafka.componentmeta;

import com.github.packageurl.MalformedPackageURLException;
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

    public SupportedMetaHandler(ComponentProjection componentProjection, QueryManager queryManager, KafkaEventDispatcher kafkaEventDispatcher, FetchMeta fetchMeta) {
        this.componentProjection = componentProjection;
        this.kafkaEventDispatcher = kafkaEventDispatcher;
        this.queryManager = queryManager;
        this.fetchMeta = fetchMeta;
    }

    @Override
    public IntegrityMetaComponent handle() throws MalformedPackageURLException {
        IntegrityMetaComponent persistentIntegrityMetaComponent = queryManager.getIntegrityMetaComponent(componentProjection.purl().toString());
        if (persistentIntegrityMetaComponent == null) {
            IntegrityMetaComponent integrityMetaComponent = queryManager.createIntegrityMetaComponent(createIntegrityMetaComponent(componentProjection.purl().toString()));
            kafkaEventDispatcher.dispatchAsync(new ComponentRepositoryMetaAnalysisEvent(componentProjection.componentUuid(),componentProjection.purl().canonicalize(), componentProjection.internal(), fetchMeta));
            return integrityMetaComponent;
        }
        if (persistentIntegrityMetaComponent.getStatus() == null || (persistentIntegrityMetaComponent.getStatus() == FetchStatus.IN_PROGRESS && Date.from(Instant.now()).getTime() - persistentIntegrityMetaComponent.getLastFetch().getTime() > TIME_SPAN)) {
            persistentIntegrityMetaComponent.setLastFetch(Date.from(Instant.now()));
            IntegrityMetaComponent updateIntegrityMetaComponent = queryManager.updateIntegrityMetaComponent(persistentIntegrityMetaComponent);
            kafkaEventDispatcher.dispatchAsync(new ComponentRepositoryMetaAnalysisEvent(componentProjection.componentUuid(), componentProjection.purl().canonicalize(), componentProjection.internal(), fetchMeta));
            return updateIntegrityMetaComponent;
        } else {
            kafkaEventDispatcher.dispatchAsync(new ComponentRepositoryMetaAnalysisEvent(componentProjection.componentUuid(), componentProjection.purl().canonicalize(), componentProjection.internal(), fetchMeta));
            return persistentIntegrityMetaComponent;
        }
    }

}