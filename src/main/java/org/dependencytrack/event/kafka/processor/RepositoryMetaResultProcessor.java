package org.dependencytrack.event.kafka.processor;

import alpine.common.logging.Logger;
import alpine.common.metrics.Metrics;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import io.micrometer.core.instrument.Timer;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.apache.kafka.streams.processor.api.Processor;
import org.apache.kafka.streams.processor.api.Record;
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
        if (record.value().hasLatestVersion()) {
            final Timer.Sample timerSample = Timer.start();
            try (final var qm = new QueryManager()) {
                synchronizeRepositoryMetaComponent(qm.getPersistenceManager(), record);
                //synchronize Integrity metadata
                //perform integrity check
            } catch (Exception e) {
                LOGGER.error("An unexpected error occurred while processing record %s".formatted(record), e);
            } finally {
                timerSample.stop(TIMER);
            }
        }
    }

    private void synchronizeRepositoryMetaComponent(final PersistenceManager pm, final Record<String, AnalysisResult> record) {
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
                trx.begin();

                final Query<RepositoryMetaComponent> query = pm.newQuery(RepositoryMetaComponent.class);
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
                        && persistentRepoMetaComponent.getLastCheck().after(new Date(record.timestamp()))) {
                    LOGGER.warn("""
                            Received repository meta information for %s that is older\s
                            than what's already in the database; Discarding
                            """.formatted(purl));
                    return;
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
                persistentRepoMetaComponent.setLastCheck(new Date(record.timestamp()));
                pm.makePersistent(persistentRepoMetaComponent);

                trx.commit();
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

            return;
        }
    }

}
