package org.dependencytrack.event.kafka.streams.processor;

import alpine.common.logging.Logger;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.dependencytrack.event.kafka.processor.api.Processor;
import org.dependencytrack.model.Epss;
import org.dependencytrack.parser.dependencytrack.EpssModelConverter;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.proto.mirror.v1.EpssItem;


public class MirrorEpssProcessor implements Processor<String, EpssItem> {

    public static final String PROCESSOR_NAME = "vuln.mirror";
    private static final Logger LOGGER = Logger.getLogger(MirrorEpssProcessor.class);

    @Override
    public void process(ConsumerRecord<String, EpssItem> record) {
        try (QueryManager qm = new QueryManager()) {
            LOGGER.debug("Synchronizing Mirrored EPSS data for CVE : " + record.key());
            EpssItem epssItem = record.value();
            final Epss epss = EpssModelConverter.convert(epssItem);
            final Epss synchronizedEpss = qm.synchronizeEpss(epss);
            qm.persist(synchronizedEpss);
        }
    }
}
