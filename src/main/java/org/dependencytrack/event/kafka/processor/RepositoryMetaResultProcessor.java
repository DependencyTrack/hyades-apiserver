package org.dependencytrack.event.kafka.processor;

import alpine.common.logging.Logger;
import alpine.common.metrics.Metrics;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import io.micrometer.core.instrument.Timer;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.apache.kafka.streams.processor.api.Processor;
import org.apache.kafka.streams.processor.api.Record;
import org.dependencytrack.model.FetchStatus;
import org.dependencytrack.model.IntegrityMetaComponent;
import org.dependencytrack.model.RepositoryMetaComponent;
import org.dependencytrack.model.RepositoryType;
import org.dependencytrack.persistence.QueryManager;
import org.hyades.proto.repometaanalysis.v1.AnalysisResult;
import org.postgresql.util.PSQLState;

import javax.jdo.JDODataStoreException;
import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import javax.jdo.Transaction;
import java.sql.SQLException;
import java.util.Date;
import java.util.Optional;

/**
 * A {@link Processor} responsible for processing result of component repository meta analyses.
 */
public class RepositoryMetaResultProcessor implements Processor<String, AnalysisResult, Void, Void> {

    private static final Logger LOGGER = Logger.getLogger(RepositoryMetaResultProcessor.class);
    private static final Timer TIMER = Timer.builder("repo_meta_result_processing")
            .description("Time taken to process repository meta analysis results")
            .register(Metrics.getRegistry());

    @Override
    public void process(final Record<String, AnalysisResult> record) {
        final Timer.Sample timerSample = Timer.start();
        try (final var qm = new QueryManager()) {
            synchronizeMetaInformationForComponent(qm, record);
        } catch (Exception e) {
            LOGGER.error("An unexpected error occurred while processing record %s".formatted(record), e);
        } finally {
            timerSample.stop(TIMER);
        }
    }

    private void synchronizeMetaInformationForComponent(final QueryManager queryManager, final Record<String, AnalysisResult> record) throws Exception {
        PersistenceManager pm = queryManager.getPersistenceManager();
        final AnalysisResult result = record.value();
        if (!result.hasComponent()) {
            LOGGER.warn("""
                    Received repository meta information without component,\s
                    will not be able to correlate; Dropping
                    """);
            return;
        }

        final PackageURL purl;
        try {
            purl = new PackageURL(result.getComponent().getPurl());
        } catch (MalformedPackageURLException e) {
            LOGGER.warn("""
                    Received repository meta information with invalid PURL,\s
                    will not be able to correlate; Dropping
                    """, e);
            return;
        }

        // It is possible that the same meta info is reported for multiple components in parallel,
        // causing unique constraint violations when attempting to insert into the REPOSITORY_META_COMPONENT table.
        // In such cases, we can get away with simply retrying to SELECT+UPDATE or INSERT again. We'll attempt
        // up to 3 times before giving up.
        for (int i = 0; i < 3; i++) {
            final Transaction trx = pm.currentTransaction();
            try {
                RepositoryMetaComponent repositoryMetaComponentResult = createRepositoryMetaResult(record, pm, purl);
                if (repositoryMetaComponentResult != null) {
                    trx.begin();
                    pm.makePersistent(repositoryMetaComponentResult);
                    trx.commit();
                    break; // this means that transaction was successful and we do not need to retry
                }
            } catch (JDODataStoreException e) {
                // TODO: DataNucleus doesn't map constraint violation exceptions very well,
                // so we have to depend on the exception of the underlying JDBC driver to
                // tell us what happened. We currently only handle PostgreSQL, but we'll have
                // to do the same for at least H2 and MSSQL.
                if (ExceptionUtils.getRootCause(e) instanceof final SQLException se
                        && PSQLState.UNIQUE_VIOLATION.getState().equals(se.getSQLState())) {
                    continue; // Retry
                }

                throw e;
            } finally {
                if (trx.isActive()) {
                    trx.rollback();
                }
            }
        }
        //snychronize integrity meta information if available
        if (result.hasIntegrityMeta()) {
            synchronizeIntegrityMetaResult(record, queryManager, purl);
        } else {
            LOGGER.debug("Incoming result for component with purl %s  does not include component integrity info".formatted(purl));
        }
    }

    private RepositoryMetaComponent createRepositoryMetaResult(Record<String, AnalysisResult> incomingAnalysisResultRecord, PersistenceManager pm, PackageURL purl) throws Exception {
        final AnalysisResult result = incomingAnalysisResultRecord.value();
        if (result.hasLatestVersion()) {
            try (final Query<RepositoryMetaComponent> query = pm.newQuery(RepositoryMetaComponent.class)) {
                query.setFilter("repositoryType == :repositoryType && namespace == :namespace && name == :name");
                query.setParameters(
                        RepositoryType.resolve(purl),
                        purl.getNamespace(),
                        purl.getName()
                );
                RepositoryMetaComponent persistentRepoMetaComponent = query.executeUnique();
                if (persistentRepoMetaComponent == null) {
                    persistentRepoMetaComponent = new RepositoryMetaComponent();
                }

                if (persistentRepoMetaComponent.getLastCheck() != null
                        && persistentRepoMetaComponent.getLastCheck().after(new Date(incomingAnalysisResultRecord.timestamp()))) {
                    LOGGER.warn("""
                            Received repository meta information for %s that is older\s
                            than what's already in the database; Discarding
                            """.formatted(purl));
                    return null;
                }

                persistentRepoMetaComponent.setRepositoryType(RepositoryType.resolve(purl));
                persistentRepoMetaComponent.setNamespace(purl.getNamespace());
                persistentRepoMetaComponent.setName(purl.getName());
                if (result.hasLatestVersion()) {
                    persistentRepoMetaComponent.setLatestVersion(result.getLatestVersion());
                }
                if (result.hasPublished()) {
                    persistentRepoMetaComponent.setPublished(new Date(result.getPublished().getSeconds() * 1000));
                }
                persistentRepoMetaComponent.setLastCheck(new Date(incomingAnalysisResultRecord.timestamp()));
                return persistentRepoMetaComponent;
            }
        } else {
            return null;
        }
    }

    private void synchronizeIntegrityMetaResult(final Record<String, AnalysisResult> incomingAnalysisResultRecord, QueryManager queryManager, PackageURL purl) {
        final AnalysisResult result = incomingAnalysisResultRecord.value();
        IntegrityMetaComponent persistentIntegrityMetaComponent = queryManager.getIntegrityMetaComponent(purl.toString());
        if (persistentIntegrityMetaComponent == null) {
            persistentIntegrityMetaComponent = new IntegrityMetaComponent();
        }

        if (persistentIntegrityMetaComponent.getStatus().equals(FetchStatus.PROCESSED)) {
            LOGGER.warn("""
                    Received hash information for %s that has already been processed; Discarding
                    """.formatted(purl));
            return;
        }
        if (result.getIntegrityMeta().hasMd5() || result.getIntegrityMeta().hasSha1() || result.getIntegrityMeta().hasSha256()
                || result.getIntegrityMeta().hasSha512() || result.getIntegrityMeta().hasCurrentVersionLastModified()) {
            Optional.ofNullable(result.getIntegrityMeta().getMd5()).ifPresent(persistentIntegrityMetaComponent::setMd5);
            Optional.ofNullable(result.getIntegrityMeta().getSha1()).ifPresent(persistentIntegrityMetaComponent::setSha1);
            Optional.ofNullable(result.getIntegrityMeta().getSha256()).ifPresent(persistentIntegrityMetaComponent::setSha256);
            Optional.ofNullable(result.getIntegrityMeta().getSha512()).ifPresent(persistentIntegrityMetaComponent::setSha512);
            persistentIntegrityMetaComponent.setPurl(result.getComponent().getPurl());
            persistentIntegrityMetaComponent.setRepositoryUrl(result.getIntegrityMeta().getMetaSourceUrl());
            persistentIntegrityMetaComponent.setPublishedAt(result.getIntegrityMeta().hasCurrentVersionLastModified() ? new Date(result.getIntegrityMeta().getCurrentVersionLastModified().getSeconds() * 1000) : null);
            persistentIntegrityMetaComponent.setStatus(FetchStatus.PROCESSED);
        } else {
            persistentIntegrityMetaComponent.setMd5(null);
            persistentIntegrityMetaComponent.setSha256(null);
            persistentIntegrityMetaComponent.setSha1(null);
            persistentIntegrityMetaComponent.setSha512(null);
            persistentIntegrityMetaComponent.setPurl(purl.toString());
            persistentIntegrityMetaComponent.setRepositoryUrl(result.getIntegrityMeta().getMetaSourceUrl());
            persistentIntegrityMetaComponent.setStatus(FetchStatus.NOT_AVAILABLE);
        }
        queryManager.updateIntegrityMetaComponent(persistentIntegrityMetaComponent);
    }

}
