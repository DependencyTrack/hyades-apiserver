package org.dependencytrack.event.kafka.streams.exception;

import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.common.errors.SerializationException;
import org.apache.kafka.streams.errors.DeserializationExceptionHandler.DeserializationHandlerResponse;
import org.apache.kafka.streams.processor.ProcessorContext;
import org.junit.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class KafkaStreamsDeserializationExceptionHandlerTest {

    @Test
    public void testHandle() {
        final var record = new ConsumerRecord<>("topic", 6, 3, "key".getBytes(), "value".getBytes());
        final var processorContext = mock(ProcessorContext.class);
        final var handler = new KafkaStreamsDeserializationExceptionHandler(Clock.systemUTC(), Duration.ofMinutes(5), 10);

        for (int i = 0; i < 9; i++) {
            assertThat(handler.handle(processorContext, record, new SerializationException())).isEqualTo(DeserializationHandlerResponse.CONTINUE);
        }

        assertThat(handler.handle(processorContext, record, new SerializationException())).isEqualTo(DeserializationHandlerResponse.FAIL);
    }

    @Test
    public void testHandleWithThresholdReset() {
        final var clockMock = mock(Clock.class);
        when(clockMock.instant())
                .thenReturn(Instant.EPOCH)
                .thenReturn(Instant.EPOCH.plusMillis(250))
                .thenReturn(Instant.EPOCH.plusSeconds(1).plusMillis(251));

        final var record = new ConsumerRecord<>("topic", 6, 3, "key".getBytes(), "value".getBytes());
        final var processorContext = mock(ProcessorContext.class);
        final var handler = new KafkaStreamsDeserializationExceptionHandler(clockMock, Duration.ofSeconds(1), 2);

        assertThat(handler.handle(processorContext, record, new SerializationException())).isEqualTo(DeserializationHandlerResponse.CONTINUE);
        assertThat(handler.handle(processorContext, record, new SerializationException())).isEqualTo(DeserializationHandlerResponse.FAIL);
        assertThat(handler.handle(processorContext, record, new SerializationException())).isEqualTo(DeserializationHandlerResponse.CONTINUE);
    }

}