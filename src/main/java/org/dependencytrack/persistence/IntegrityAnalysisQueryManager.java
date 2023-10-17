package org.dependencytrack.persistence;

import alpine.resources.AlpineRequest;
import org.dependencytrack.model.IntegrityAnalysis;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import java.util.UUID;

public class IntegrityAnalysisQueryManager extends QueryManager implements IQueryManager {

    IntegrityAnalysisQueryManager(final PersistenceManager pm) {
        super(pm);
    }

    IntegrityAnalysisQueryManager(final PersistenceManager pm, final AlpineRequest request) {
        super(pm, request);
    }

    public IntegrityAnalysis getIntegrityAnalysisByComponentUuid(UUID uuid) {
        final Query<IntegrityAnalysis> query = pm.newQuery(IntegrityAnalysis.class);
        query.setFilter("component.uuid == :uuid");
        query.setParameters(uuid);
        return query.executeUnique();
    }
}
