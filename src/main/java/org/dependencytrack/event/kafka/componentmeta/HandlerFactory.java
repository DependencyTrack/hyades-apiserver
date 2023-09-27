package org.dependencytrack.event.kafka.componentmeta;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import org.dependencytrack.event.kafka.KafkaEventDispatcher;
import org.dependencytrack.persistence.QueryManager;

public class HandlerFactory {

    public static Handler createHandler(ComponentProjection componentProjection, QueryManager queryManager, KafkaEventDispatcher kafkaEventDispatcher, boolean fetchLatestVersion) throws MalformedPackageURLException {
        PackageURL packageURL = new PackageURL(componentProjection.purl());
        boolean result = RepoMetaConstants.SUPPORTED_PACKAGE_URLS_FOR_INTEGRITY_CHECK.contains(packageURL.getType());
        if (result) {
            return new SupportedMetaHandler(componentProjection, queryManager, kafkaEventDispatcher, fetchLatestVersion);
        } else {
            return new UnSupportedMetaHandler(componentProjection, queryManager, kafkaEventDispatcher, fetchLatestVersion);
        }
    }
}
