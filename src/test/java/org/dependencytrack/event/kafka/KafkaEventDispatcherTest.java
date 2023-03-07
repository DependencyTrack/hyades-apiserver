package org.dependencytrack.event.kafka;

import alpine.notification.Notification;
import alpine.notification.NotificationLevel;
import org.apache.kafka.clients.producer.MockProducer;
import org.apache.kafka.clients.producer.RecordMetadata;
import org.apache.kafka.common.serialization.ByteArraySerializer;
import org.dependencytrack.event.ComponentVulnerabilityAnalysisEvent;
import org.dependencytrack.event.NistMirrorEvent;
import org.dependencytrack.event.OsvMirrorEvent;
import org.dependencytrack.event.PortfolioMetricsUpdateEvent;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.VulnerabilityAnalysisLevel;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.junit.Before;
import org.junit.Test;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

public class KafkaEventDispatcherTest {

    private MockProducer<byte[], byte[]> mockProducer;

    @Before
    public void setUp() {
        mockProducer = new MockProducer<>(true, new ByteArraySerializer(), new ByteArraySerializer());
    }

    @Test
    public void testDispatch() {
        final var component = new Component();
        component.setUuid(UUID.randomUUID());
        component.setName("foobar");

        final var event = new ComponentVulnerabilityAnalysisEvent(UUID.randomUUID(), component, VulnerabilityAnalysisLevel.BOM_UPLOAD_ANALYSIS);

        final var dispatcher = new KafkaEventDispatcher(mockProducer);
        final RecordMetadata recordMeta = dispatcher.dispatch(event);
        assertThat(recordMeta.topic()).isEqualTo(KafkaTopics.VULN_ANALYSIS_COMMAND.name());
        assertThat(mockProducer.history()).hasSize(1);
    }

    @Test
    public void testDispatchMirrorEvents() {
        final var eventOsv = new OsvMirrorEvent("npm");
        var dispatcher = new KafkaEventDispatcher(mockProducer);
        RecordMetadata recordMeta = dispatcher.dispatch(eventOsv);
        assertThat(recordMeta.topic()).isEqualTo(KafkaTopics.MIRROR_OSV.name());
        assertThat(mockProducer.history()).hasSize(1);

        final var eventNvd = new NistMirrorEvent();
        dispatcher = new KafkaEventDispatcher(mockProducer);
        recordMeta = dispatcher.dispatch(eventNvd);
        assertThat(recordMeta.topic()).isEqualTo(KafkaTopics.MIRROR_NVD.name());
        assertThat(mockProducer.history()).hasSize(2);
    }

    @Test
    public void testDispatchWithUnsupportedEvent() {
        final var dispatcher = new KafkaEventDispatcher(mockProducer);
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> dispatcher.dispatch(new PortfolioMetricsUpdateEvent()));
        assertThat(mockProducer.history()).isEmpty();
    }

    @Test
    public void testDispatchNotification() {
        final var notification = new Notification()
                .scope(NotificationScope.PORTFOLIO)
                .group(NotificationGroup.NEW_VULNERABILITY)
                .level(NotificationLevel.INFORMATIONAL);

        final var dispatcher = new KafkaEventDispatcher(mockProducer);
        final RecordMetadata recordMeta = dispatcher.dispatchNotification(notification);
        assertThat(recordMeta.topic()).isEqualTo(KafkaTopics.NOTIFICATION_NEW_VULNERABILITY.name());
        assertThat(mockProducer.history()).hasSize(1);
    }

}