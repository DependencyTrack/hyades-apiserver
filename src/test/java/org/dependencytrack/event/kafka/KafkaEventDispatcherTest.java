package org.dependencytrack.event.kafka;

import org.apache.kafka.clients.producer.MockProducer;
import org.apache.kafka.clients.producer.RecordMetadata;
import org.apache.kafka.common.serialization.StringSerializer;
import org.dependencytrack.event.ComponentVulnerabilityAnalysisEvent;
import org.dependencytrack.event.PortfolioMetricsUpdateEvent;
import org.dependencytrack.event.kafka.serialization.JacksonSerializer;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.VulnerabilityAnalysisLevel;
import org.junit.Before;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

public class KafkaEventDispatcherTest {

    private MockProducer<String, Object> mockProducer;

    @Before
    public void setUp() {
        mockProducer = new MockProducer<>(true, new StringSerializer(), new JacksonSerializer());
    }

    @Test
    public void testDispatch() {
        final var component = new Component();
        component.setName("foobar");

        final var event = new ComponentVulnerabilityAnalysisEvent(component, VulnerabilityAnalysisLevel.BOM_UPLOAD_ANALYSIS);

        final var dispatcher = new KafkaEventDispatcher(mockProducer);
        final RecordMetadata recordMeta = dispatcher.dispatch(event);
        assertThat(recordMeta.topic()).isEqualTo(KafkaTopic.COMPONENT_ANALYSIS.getName());
        assertThat(mockProducer.history()).hasSize(1);
    }

    @Test
    public void testDispatchWithUnsupportedEvent() {
        final var dispatcher = new KafkaEventDispatcher(mockProducer);
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> dispatcher.dispatch(new PortfolioMetricsUpdateEvent()));
        assertThat(mockProducer.history()).isEmpty();
    }

}