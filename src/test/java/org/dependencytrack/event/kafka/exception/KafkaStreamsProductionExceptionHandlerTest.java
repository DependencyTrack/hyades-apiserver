package org.dependencytrack.event.kafka.exception;

import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.errors.RecordTooLargeException;
import org.apache.kafka.streams.errors.ProductionExceptionHandler.ProductionExceptionHandlerResponse;
import org.junit.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

public class KafkaStreamsProductionExceptionHandlerTest {

    @Test
    public void testHandle() {
        final var record = new ProducerRecord<>("topic", 6, "key".getBytes(), "value".getBytes());
        final var handler = new KafkaStreamsProductionExceptionHandler(Duration.ofMinutes(5), 10);

        for (int i = 0; i < 9; i++) {
            assertThat(handler.handle(record, new RecordTooLargeException())).isEqualTo(ProductionExceptionHandlerResponse.CONTINUE);
        }

        assertThat(handler.handle(record, new RecordTooLargeException())).isEqualTo(ProductionExceptionHandlerResponse.FAIL);
    }

    @Test
    public void testHandleWithThresholdReset() {
        final var record = new ProducerRecord<>("topic", 6, "key".getBytes(), "value".getBytes());
        final var handler = new KafkaStreamsProductionExceptionHandler(Duration.ofMillis(250), 2);

        assertThat(handler.handle(record, new RecordTooLargeException())).isEqualTo(ProductionExceptionHandlerResponse.CONTINUE);
        assertThat(handler.handle(record, new RecordTooLargeException())).isEqualTo(ProductionExceptionHandlerResponse.FAIL);

        await()
                .atMost(Duration.ofMillis(500))
                .untilAsserted(() -> assertThat(handler.handle(record, new RecordTooLargeException())).isEqualTo(ProductionExceptionHandlerResponse.CONTINUE));
    }

    @Test
    public void testHandleWithUnexpectedException() {
        final var record = new ProducerRecord<>("topic", 6, "key".getBytes(), "value".getBytes());
        final var handler = new KafkaStreamsProductionExceptionHandler(Duration.ofMinutes(5), 10);

        assertThat(handler.handle(record, new IllegalStateException())).isEqualTo(ProductionExceptionHandlerResponse.FAIL);
    }

}