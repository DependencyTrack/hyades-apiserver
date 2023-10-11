package org.dependencytrack.event.kafka.componentmeta;

import alpine.common.logging.Logger;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import org.dependencytrack.AbstractPostgresEnabledTest;
import org.dependencytrack.event.kafka.KafkaEventDispatcher;
import org.dependencytrack.event.kafka.KafkaTopics;
import org.dependencytrack.model.IntegrityMetaComponent;
import org.dependencytrack.util.PurlUtil;
import org.hyades.proto.repometaanalysis.v1.FetchMeta;
import org.junit.Test;
import org.junit.jupiter.api.Assertions;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.util.KafkaTestUtil.deserializeValue;

public class UnSupportedMetaHandlerTest extends AbstractPostgresEnabledTest {

    private static final Logger LOGGER = Logger.getLogger(SupportedMetaHandlerTest.class);

    @Test
    public void testHandleComponentInDb() {
        Handler handler;
        KafkaEventDispatcher kafkaEventDispatcher = new KafkaEventDispatcher();
        try {
            PackageURL packageUrl = new PackageURL("pkg:golang/foo/bar@baz?ping=pong#1/2/3");
            ComponentProjection componentProjection = new ComponentProjection(PurlUtil.silentPurlCoordinatesOnly(packageUrl).toString(), false, packageUrl);
            IntegrityMetaComponent integrityMetaComponent = qm.getIntegrityMetaComponent(componentProjection.purl().toString());
            Assertions.assertNull(integrityMetaComponent);
            handler = HandlerFactory.createHandler(componentProjection, qm, kafkaEventDispatcher, FetchMeta.FETCH_META_LATEST_VERSION);
            handler.handle();
            assertThat(kafkaMockProducer.history()).satisfiesExactly(
                    record -> {
                        assertThat(record.topic()).isEqualTo(KafkaTopics.REPO_META_ANALYSIS_COMMAND.name());
                        final var command = deserializeValue(KafkaTopics.REPO_META_ANALYSIS_COMMAND, record);
                        assertThat(command.getComponent().getPurl()).isEqualTo("pkg:golang/foo/bar@baz");
                        assertThat(command.getComponent().getInternal()).isFalse();
                        assertThat(command.getFetchMeta()).isEqualTo(FetchMeta.FETCH_META_LATEST_VERSION);
                    }

            );
            Assertions.assertNull(integrityMetaComponent);

        } catch (MalformedPackageURLException ex) {
            LOGGER.warn("Package url not formed correctly");
        }
    }
}