package org.dependencytrack.event.kafka.processor.api;

import io.confluent.parallelconsumer.PollContext;

interface RecordProcessingStrategy {

    /**
     * Handle the result of a consumer poll.
     *
     * @param pollCtx The context of the current consumer poll
     */
    void handlePoll(final PollContext<byte[], byte[]> pollCtx);

}
