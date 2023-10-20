package org.dependencytrack.util;

import com.github.packageurl.PackageURL;
import org.dependencytrack.model.ComponentMetaInformation;
import org.dependencytrack.model.IntegrityAnalysis;
import org.dependencytrack.model.IntegrityMatchStatus;
import org.dependencytrack.model.IntegrityMetaComponent;
import org.dependencytrack.persistence.QueryManager;

import java.util.Date;
import java.util.UUID;

public class ComponentMetaInformationUtil {

    public static ComponentMetaInformation getMetaInformation(PackageURL purl, UUID uuid) {
        Date publishedAt = null;
        Date lastFetched = null;
        IntegrityMatchStatus integrityMatchStatus = null;
        try (QueryManager queryManager = new QueryManager()) {
            final IntegrityMetaComponent integrityMetaComponent = queryManager.getIntegrityMetaComponent(purl.toString());
            final IntegrityAnalysis integrityAnalysis = queryManager.getIntegrityAnalysisByComponentUuid(uuid);
            if (integrityMetaComponent != null) {
                publishedAt = integrityMetaComponent.getPublishedAt();
                lastFetched = integrityMetaComponent.getLastFetch();
            }
            if (integrityAnalysis != null) {
                integrityMatchStatus = integrityAnalysis.getIntegrityCheckStatus();
            }
        }
        return new ComponentMetaInformation(publishedAt, integrityMatchStatus, lastFetched);
    }
}
