package org.dependencytrack.event.kafka.processor;

import alpine.common.logging.Logger;
import org.apache.kafka.streams.processor.api.Processor;
import org.apache.kafka.streams.processor.api.Record;
import org.dependencytrack.model.RepositoryMetaComponent;
import org.dependencytrack.model.RepositoryType;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.tasks.repositories.MetaModel;

import java.util.Date;
import java.util.UUID;

public class RepositoryMetaResultProcessor implements Processor<UUID, MetaModel, Void, Void> {

    private static final Logger LOGGER = Logger.getLogger(RepositoryMetaResultProcessor.class);

    @Override
    public void process(final Record<UUID, MetaModel> record) {
        final MetaModel result = record.value();

        LOGGER.info("Received repository meta analysis result");
        LOGGER.info(" - Component: " + result.getComponent());
        if (result.getLatestVersion() != null) {
            LOGGER.info(" - Latest version: " + result.getLatestVersion());
            try (final var qm = new QueryManager()) {
                final var metaComponent = new RepositoryMetaComponent();
                metaComponent.setRepositoryType(RepositoryType.resolve(result.getComponent().getPurl()));
                metaComponent.setNamespace(result.getComponent().getPurl().getNamespace());
                metaComponent.setName(result.getComponent().getPurl().getName());
                metaComponent.setPublished(result.getPublishedTimestamp());
                metaComponent.setLatestVersion(result.getLatestVersion());
                metaComponent.setLastCheck(new Date());
                qm.synchronizeRepositoryMetaComponent(metaComponent);
            }
        } else {
            LOGGER.info(" - No meta information");
        }
    }

}
