package org.dependencytrack.event.kafka.processor;

import alpine.common.logging.Logger;
import alpine.common.metrics.Metrics;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import io.micrometer.core.instrument.Timer;
import org.apache.kafka.streams.processor.api.Processor;
import org.apache.kafka.streams.processor.api.Record;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.IntegrityAnalysisComponent;
import org.dependencytrack.persistence.QueryManager;
import org.hyades.proto.repometaanalysis.v1.HashMatchStatus;
import org.hyades.proto.repometaanalysis.v1.IntegrityResult;

import javax.jdo.JDODataStoreException;
import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import javax.jdo.Transaction;
import java.util.Date;
import java.util.UUID;

public class IntegrityAnalysiResultProcessor implements Processor<String, IntegrityResult, Void, Void> {
    private static final Logger LOGGER = Logger.getLogger(IntegrityAnalysiResultProcessor.class);
    private static final Timer TIMER = Timer.builder("repo_meta_result_processing")
            .description("Time taken to process repository meta analysis results")
            .register(Metrics.getRegistry());

    @Override
    public void process(Record<String, IntegrityResult> record) {
        final Timer.Sample timerSample = Timer.start();
        try (final var qm = new QueryManager()) {
            synchronizeComponentIntegrity(qm.getPersistenceManager(), record);
        } catch (Exception e) {
            LOGGER.error("An unexpected error occurred while processing record %s".formatted(record), e);
        } finally {
            timerSample.stop(TIMER);
        }
    }

    private void synchronizeComponentIntegrity(final PersistenceManager pm, final Record<String, IntegrityResult> record) {

        final IntegrityResult result = record.value();

        final PackageURL purl;
        try {
            purl = new PackageURL(result.getComponent().getPurl());
        } catch (MalformedPackageURLException e) {
            LOGGER.warn("""
                    Received repository integrity information with invalid PURL,\s
                    will not be able to correlate; Dropping
                    """, e);
            return;
        }

        final Transaction trx = pm.currentTransaction();
        try {
            trx.begin();
            final Query<IntegrityAnalysisComponent> query = pm.newQuery(IntegrityAnalysisComponent.class);
            query.setFilter("repositoryIdentifier == :repository && component.id == :id && component.uuid == :uuid");
            query.setParameters(
                    record.value().getRepository(),
                    record.value().getComponent().getComponentId(),
                    UUID.fromString(record.value().getComponent().getUuid())
            );
            IntegrityAnalysisComponent persistentIntegrityResult = query.executeUnique();
            if (persistentIntegrityResult == null || persistentIntegrityResult.getComponent() == null) {
                persistentIntegrityResult = new IntegrityAnalysisComponent();
            }

            if (persistentIntegrityResult.getLastCheck() != null
                    && persistentIntegrityResult.getLastCheck().after(new Date(record.timestamp()))) {
                LOGGER.warn("""
                        Received integrity check information for %s that is older\s
                        than what's already in the database; Discarding
                        """.formatted(purl));
                return;
            }
            final Query<Component> queryComponent = pm.newQuery(Component.class);
            queryComponent.setFilter("id == :id");
            queryComponent.setParameters(record.value().getComponent().getComponentId());
            Component component = queryComponent.executeUnique();
            persistentIntegrityResult.setRepositoryIdentifier(record.value().getRepository());
            HashMatchStatus md5HashMatch = record.value().getMd5HashMatch();
            HashMatchStatus sha1HashMatch = record.value().getSha1HashMatch();
            HashMatchStatus sha256HashMatch = record.value().getSha256HashMatch();
            persistentIntegrityResult.setMd5HashMatched(md5HashMatch.name());
            persistentIntegrityResult.setSha256HashMatched(sha256HashMatch.name());
            persistentIntegrityResult.setSha1HashMatched(sha1HashMatch.name());
            persistentIntegrityResult.setComponent(component);
            persistentIntegrityResult.setLastCheck(new Date(record.timestamp()));
            if (md5HashMatch.equals(HashMatchStatus.HASH_MATCH_STATUS_FAIL) || sha1HashMatch.equals(HashMatchStatus.HASH_MATCH_STATUS_FAIL) || sha256HashMatch.equals(HashMatchStatus.HASH_MATCH_STATUS_FAIL)) {
                persistentIntegrityResult.setIntegrityCheckPassed(false);
            } else if (md5HashMatch.equals(HashMatchStatus.HASH_MATCH_STATUS_UNKNOWN) && sha1HashMatch.equals(HashMatchStatus.HASH_MATCH_STATUS_UNKNOWN) && sha256HashMatch.equals(HashMatchStatus.HASH_MATCH_STATUS_UNKNOWN)) {
                persistentIntegrityResult.setIntegrityCheckPassed(false);
            } else if (md5HashMatch.equals(HashMatchStatus.HASH_MATCH_STATUS_COMPONENT_MISSING_HASH) && sha1HashMatch.equals(HashMatchStatus.HASH_MATCH_STATUS_COMPONENT_MISSING_HASH) && sha256HashMatch.equals(HashMatchStatus.HASH_MATCH_STATUS_COMPONENT_MISSING_HASH)) {
                persistentIntegrityResult.setIntegrityCheckPassed(false);
            } else {
                boolean flag = (md5HashMatch.equals(HashMatchStatus.HASH_MATCH_STATUS_PASS) || md5HashMatch.equals(HashMatchStatus.HASH_MATCH_STATUS_UNKNOWN))
                        && (sha1HashMatch.equals(HashMatchStatus.HASH_MATCH_STATUS_PASS) || sha1HashMatch.equals(HashMatchStatus.HASH_MATCH_STATUS_UNKNOWN))
                        && (sha256HashMatch.equals(HashMatchStatus.HASH_MATCH_STATUS_PASS) || sha256HashMatch.equals(HashMatchStatus.HASH_MATCH_STATUS_UNKNOWN));
                persistentIntegrityResult.setIntegrityCheckPassed(flag);
            }
            pm.makePersistent(persistentIntegrityResult);

            trx.commit();
        } catch (JDODataStoreException e) {
            throw e;
        } finally {
            if (trx.isActive()) {
                trx.rollback();
            }
        }
    }
}
