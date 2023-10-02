package org.dependencytrack.event.kafka.componentmeta;

import alpine.common.logging.Logger;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import org.dependencytrack.AbstractPostgresEnabledTest;
import org.dependencytrack.event.kafka.KafkaEventDispatcher;
import org.dependencytrack.event.kafka.KafkaTopics;
import org.dependencytrack.model.FetchStatus;
import org.dependencytrack.model.IntegrityMetaComponent;
import org.dependencytrack.util.PurlUtil;
import org.junit.Test;
import org.junit.jupiter.api.Assertions;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.util.KafkaTestUtil.deserializeValue;

public class SupportedMetaHandlerTest extends AbstractPostgresEnabledTest {
    private static final Logger LOGGER = Logger.getLogger(SupportedMetaHandlerTest.class);

    @Test
    public void testHandleIntegrityComponentNotInDB() {
        Handler handler;
        KafkaEventDispatcher kafkaEventDispatcher = new KafkaEventDispatcher();
        try {
            PackageURL packageUrl = new PackageURL("pkg:maven/org.http4s/blaze-core_2.12");
            ComponentProjection componentProjection = new ComponentProjection(PurlUtil.silentPurlCoordinatesOnly(packageUrl).toString(), false, packageUrl.toString());
            IntegrityMetaComponent integrityMetaComponent = qm.getIntegrityMetaComponent(componentProjection.purl());
            Assertions.assertNull(integrityMetaComponent);
            handler = HandlerFactory.createHandler(componentProjection, qm, kafkaEventDispatcher, false);
            IntegrityMetaComponent result = handler.handle();
            assertThat(kafkaMockProducer.history()).satisfiesExactly(
                    record -> {
                        assertThat(record.topic()).isEqualTo(KafkaTopics.REPO_META_ANALYSIS_COMMAND.name());
                        final var command = deserializeValue(KafkaTopics.REPO_META_ANALYSIS_COMMAND, record);
                        assertThat(command.getComponent().getPurl()).isEqualTo("pkg:maven/org.http4s/blaze-core_2.12");
                        assertThat(command.getComponent().getInternal()).isFalse();
                        assertThat(command.getFetchIntegrityData()).isTrue();
                        assertThat(command.getFetchLatestVersion()).isFalse();
                    }

            );
            Assertions.assertEquals(FetchStatus.IN_PROGRESS, result.getStatus());

        } catch (MalformedPackageURLException ex) {
            LOGGER.warn("Package url not formed correctly");
        }
    }

    @Test
    public void testHandleIntegrityComponentInDB() {
        Handler handler;
        KafkaEventDispatcher kafkaEventDispatcher = new KafkaEventDispatcher();
        try {
            PackageURL packageUrl = new PackageURL("pkg:maven/org.http4s/blaze-core_2.12");
            ComponentProjection componentProjection = new ComponentProjection(PurlUtil.silentPurlCoordinatesOnly(packageUrl).toString(), false, packageUrl.toString());
            var integrityMeta = new IntegrityMetaComponent();
            integrityMeta.setPurl("pkg:maven/org.http4s/blaze-core_2.12");
            integrityMeta.setStatus(FetchStatus.IN_PROGRESS);
            integrityMeta.setLastFetch(Date.from(Instant.now().minus(2, ChronoUnit.MINUTES)));
            qm.createIntegrityMetaComponent(integrityMeta);
            handler = HandlerFactory.createHandler(componentProjection, qm, kafkaEventDispatcher, false);
            IntegrityMetaComponent result = handler.handle();
            assertThat(kafkaMockProducer.history()).satisfiesExactly(
                    record -> {
                        assertThat(record.topic()).isEqualTo(KafkaTopics.REPO_META_ANALYSIS_COMMAND.name());
                        final var command = deserializeValue(KafkaTopics.REPO_META_ANALYSIS_COMMAND, record);
                        assertThat(command.getComponent().getPurl()).isEqualTo("pkg:maven/org.http4s/blaze-core_2.12");
                        assertThat(command.getComponent().getInternal()).isFalse();
                        assertThat(command.getFetchIntegrityData()).isFalse();
                        assertThat(command.getFetchLatestVersion()).isFalse();
                    }

            );
            Assertions.assertEquals(FetchStatus.IN_PROGRESS, result.getStatus());

        } catch (MalformedPackageURLException ex) {
            LOGGER.warn("Package url not formed correctly");
        }

    }

    @Test
    public void testHandleIntegrityComponentInDBForMoreThanAnHour() {
        Handler handler;
        KafkaEventDispatcher kafkaEventDispatcher = new KafkaEventDispatcher();
        try {
            PackageURL packageUrl = new PackageURL("pkg:maven/org.http4s/blaze-core_2.12");
            ComponentProjection componentProjection = new ComponentProjection(PurlUtil.silentPurlCoordinatesOnly(packageUrl).toString(), false, packageUrl.toString());
            var integrityMeta = new IntegrityMetaComponent();
            integrityMeta.setPurl("pkg:maven/org.http4s/blaze-core_2.12");
            integrityMeta.setStatus(FetchStatus.IN_PROGRESS);
            integrityMeta.setLastFetch(Date.from(Instant.now().minus(2, ChronoUnit.HOURS)));
            qm.createIntegrityMetaComponent(integrityMeta);
            handler = HandlerFactory.createHandler(componentProjection, qm, kafkaEventDispatcher, false);
            IntegrityMetaComponent integrityMetaComponent = handler.handle();
            assertThat(kafkaMockProducer.history()).satisfiesExactly(
                    record -> {
                        assertThat(record.topic()).isEqualTo(KafkaTopics.REPO_META_ANALYSIS_COMMAND.name());
                        final var command = deserializeValue(KafkaTopics.REPO_META_ANALYSIS_COMMAND, record);
                        assertThat(command.getComponent().getPurl()).isEqualTo("pkg:maven/org.http4s/blaze-core_2.12");
                        assertThat(command.getComponent().getInternal()).isFalse();
                        assertThat(command.getFetchIntegrityData()).isTrue();
                        assertThat(command.getFetchLatestVersion()).isFalse();
                    }

            );
            Assertions.assertEquals(FetchStatus.IN_PROGRESS, integrityMetaComponent.getStatus());
            assertThat(integrityMetaComponent.getLastFetch()).isAfter(Date.from(Instant.now().minus(2, ChronoUnit.MINUTES)));

        } catch (MalformedPackageURLException ex) {
            LOGGER.warn("Package url not formed correctly");
        }
    }
}
