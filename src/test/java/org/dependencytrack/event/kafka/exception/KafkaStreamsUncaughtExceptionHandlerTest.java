package org.dependencytrack.event.kafka.exception;

import org.apache.kafka.streams.errors.StreamsUncaughtExceptionHandler.StreamThreadExceptionResponse;
import org.junit.Test;

import java.time.Duration;
import java.util.concurrent.TimeoutException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

public class KafkaStreamsUncaughtExceptionHandlerTest {

    @Test
    public void testHandleWithTransientError() {
        final var handler = new KafkaStreamsUncaughtExceptionHandler();
        assertThat(handler.handle(new TimeoutException())).isEqualTo(StreamThreadExceptionResponse.REPLACE_THREAD);
    }

    @Test
    public void testHandleWithNonTransientError() {
        final var handler = new KafkaStreamsUncaughtExceptionHandler();
        assertThat(handler.handle(new IllegalStateException())).isEqualTo(StreamThreadExceptionResponse.SHUTDOWN_CLIENT);
    }

    @Test
    public void testHandleWithTransientErrorExceedingThreshold() {
        final var handler = new KafkaStreamsUncaughtExceptionHandler(Duration.ofMinutes(5), 10);

        for (int i = 0; i < 9; i++) {
            assertThat(handler.handle(new TimeoutException())).isEqualTo(StreamThreadExceptionResponse.REPLACE_THREAD);
        }

        assertThat(handler.handle(new TimeoutException())).isEqualTo(StreamThreadExceptionResponse.SHUTDOWN_CLIENT);
    }

    @Test
    public void testHandleWithTransientErrorThresholdReset() {
        final var handler = new KafkaStreamsUncaughtExceptionHandler(Duration.ofMillis(250), 2);

        assertThat(handler.handle(new TimeoutException())).isEqualTo(StreamThreadExceptionResponse.REPLACE_THREAD);
        assertThat(handler.handle(new TimeoutException())).isEqualTo(StreamThreadExceptionResponse.SHUTDOWN_CLIENT);

        await()
                .atMost(Duration.ofMillis(500))
                .untilAsserted(() -> assertThat(handler.handle(new TimeoutException())).isEqualTo(StreamThreadExceptionResponse.REPLACE_THREAD));
    }

}