package org.dependencytrack.event.kafka.streams.processor;

import alpine.common.logging.Logger;
import alpine.common.metrics.Metrics;
import io.micrometer.core.instrument.Timer;
import org.apache.kafka.streams.processor.api.Processor;
import org.apache.kafka.streams.processor.api.Record;
import org.dependencytrack.model.Epss;
import org.dependencytrack.parser.dependencytrack.EpssModelConverter;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.proto.mirror.v1.EpssItem;


public class MirrorEpssProcessor implements Processor<String, EpssItem, Void, Void> {

    private static final Logger LOGGER = Logger.getLogger(MirrorEpssProcessor.class);
    private static final Timer TIMER = Timer.builder("epss_mirror_processing")
            .description("Time taken to process mirrored Epss data")
            .register(Metrics.getRegistry());

    @Override
    public void process(final Record<String, EpssItem> record) {
        final Timer.Sample timerSample = Timer.start();
        try (QueryManager qm = new QueryManager().withL2CacheDisabled()) {
            LOGGER.debug("Synchronizing Mirrored EPSS data for CVE : " + record.key());
            EpssItem epssItem = record.value();
            final Epss epss = EpssModelConverter.convert(epssItem);
            final Epss synchronizedEpss = qm.synchronizeEpss(epss);
            qm.persist(synchronizedEpss);
        } catch (Exception e) {
            LOGGER.error("Synchronizing Epss for %s failed".formatted(record.key()), e);
        } finally {
            timerSample.stop(TIMER);
        }
    }
}
