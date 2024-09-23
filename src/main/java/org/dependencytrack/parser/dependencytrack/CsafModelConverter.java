package org.dependencytrack.parser.dependencytrack;

import org.dependencytrack.model.CsafDocumentEntity;
import org.dependencytrack.proto.mirror.v1.CsafDocumentItem;

import java.time.Instant;

/**
 * A utility class that converts a {@link CsafDocumentItem} (which is transferred
 * over Kafka) to a {@link CsafDocumentEntity} (which is persisted into the database).
 */
public final class CsafModelConverter {
    public static CsafDocumentEntity convert(final CsafDocumentItem item) {
        final CsafDocumentEntity doc = new CsafDocumentEntity();
        doc.setPublisherNamespace(item.getPublisherNamespace());
        doc.setTrackingID(item.getTrackingId());
        doc.setTrackingVersion(item.getTrackingVersion());
        doc.setName(item.getName());
        doc.setContent(item.getJsonContent().toStringUtf8());
        doc.setSeen(item.getSeen());
        if (item.hasLastFetched()) {
            doc.setLastFetched(Instant.ofEpochSecond(item.getLastFetched().getSeconds()));
        }
        if (item.hasUrl()) {
            doc.setUrl(item.getUrl());
        }

        return doc;
    }
}
