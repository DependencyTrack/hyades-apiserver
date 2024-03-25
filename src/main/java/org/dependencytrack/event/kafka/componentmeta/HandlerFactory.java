package org.dependencytrack.event.kafka.componentmeta;

import com.github.packageurl.MalformedPackageURLException;
import org.dependencytrack.event.kafka.KafkaEventDispatcher;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.proto.repometaanalysis.v1.FetchMeta;

public class HandlerFactory {

    public static Handler createHandler(ComponentProjection componentProjection, QueryManager queryManager, KafkaEventDispatcher kafkaEventDispatcher, FetchMeta fetchMeta) throws MalformedPackageURLException {
        boolean result = RepoMetaConstants.SUPPORTED_PACKAGE_URLS_FOR_INTEGRITY_CHECK.contains(componentProjection.purl().getType());
        if (result) {
            return new SupportedMetaHandler(componentProjection, queryManager, kafkaEventDispatcher, fetchMeta);
        } else {
            return new UnSupportedMetaHandler(componentProjection, queryManager, kafkaEventDispatcher, FetchMeta.FETCH_META_LATEST_VERSION);
        }
    }
}