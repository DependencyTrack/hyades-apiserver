package org.dependencytrack.persistence;

import org.dependencytrack.model.Epss;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;

final class EpssQueryManager extends QueryManager implements IQueryManager {

    /**
     * Constructs a new QueryManager.
     *
     * @param pm a PersistenceManager object
     */
    EpssQueryManager(final PersistenceManager pm) {
        super(pm);
    }

    /**
     * Synchronizes a Epss record. Method first checkes to see if the record already
     * exists and if so, updates it. If the record does not already exist,
     * this method will create a new Epss record.
     * @param epss the Epss record to synchronize
     * @return a Epss object
     */
    public Epss synchronizeEpss(Epss epss) {
        Epss result = updateEpss(epss);
        if (result == null) {
            final Epss epssNew = persist(epss);
            return epssNew;
        }
        return result;
    }

    private Epss updateEpss(Epss epss) {
        var epssExisting = getEpssByCveId(epss.getCve());
        if (epssExisting != null) {
            epssExisting.setEpss(epss.getEpss());
            epssExisting.setPercentile(epss.getPercentile());
            return epssExisting;
        }
        return null;
    }

    /**
     * Returns a Epss record by its CVE id.
     * @param cveId the CVE id of the record
     * @return the matching Epss object, or null if not found
     */
    public Epss getEpssByCveId(String cveId) {
        final Query<Epss> query = pm.newQuery(Epss.class, "cve == :cveId");
        query.setRange(0, 1);
        return singleResult(query.execute(cveId));
    }
}
