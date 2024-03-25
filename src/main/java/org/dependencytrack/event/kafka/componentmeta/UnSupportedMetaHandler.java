package org.dependencytrack.event.kafka.componentmeta;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import org.dependencytrack.event.ComponentRepositoryMetaAnalysisEvent;
import org.dependencytrack.event.kafka.KafkaEventDispatcher;
import org.dependencytrack.model.IntegrityMetaComponent;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.proto.repometaanalysis.v1.FetchMeta;

public class UnSupportedMetaHandler extends AbstractMetaHandler {

    public UnSupportedMetaHandler(ComponentProjection componentProjection, QueryManager queryManager, KafkaEventDispatcher kafkaEventDispatcher, FetchMeta fetchMeta) {
        this.componentProjection = componentProjection;
        this.kafkaEventDispatcher = kafkaEventDispatcher;
        this.queryManager = queryManager;
        this.fetchMeta = fetchMeta;
    }

    @Override
    public IntegrityMetaComponent handle() throws MalformedPackageURLException {
        kafkaEventDispatcher.dispatchAsync(new ComponentRepositoryMetaAnalysisEvent(null, new PackageURL(componentProjection.purlCoordinates()).canonicalize(), componentProjection.internal(), fetchMeta));
        return null;
    }
}