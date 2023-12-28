package org.dependencytrack.event.kafka.processor.api;

import alpine.common.logging.Logger;
import io.confluent.parallelconsumer.PCRetriableException;
import io.confluent.parallelconsumer.ParallelStreamProcessor;
import io.confluent.parallelconsumer.PollContext;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.errors.SerializationException;
import org.apache.kafka.common.serialization.Deserializer;
import org.apache.kafka.common.serialization.Serializer;
import org.dependencytrack.event.kafka.processor.exception.RecordProcessingException;
import org.dependencytrack.event.kafka.processor.exception.RetryableRecordProcessingException;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * A {@link RecordProcessingStrategy} that processes records in batches.
 *
 * @param <CK> Type of the {@link ConsumerRecord} key
 * @param <CV> Type of the {@link ConsumerRecord} value
 * @param <PK> Type of the {@link ProducerRecord} key
 * @param <PV> Type of the {@link ProducerRecord} value
 */
public class RecordBatchProcessingStrategy<CK, CV, PK, PV> extends AbstractRecordProcessingStrategy<CK, CV, PK, PV> {

    private static final Logger LOGGER = Logger.getLogger(RecordBatchProcessingStrategy.class);

    private final RecordBatchProcessor<CK, CV, PK, PV> batchRecordProcessor;

    public RecordBatchProcessingStrategy(final RecordBatchProcessor<CK, CV, PK, PV> batchRecordProcessor,
                                         final Deserializer<CK> keyDeserializer, final Deserializer<CV> valueDeserializer,
                                         final Serializer<PK> keySerializer, final Serializer<PV> valueSerializer) {
        super(keyDeserializer, valueDeserializer, keySerializer, valueSerializer);
        this.batchRecordProcessor = batchRecordProcessor;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void process(final ParallelStreamProcessor<byte[], byte[]> streamProcessor) {
        if (!canProduce(batchRecordProcessor)) {
            streamProcessor.pollAndProduceMany(this::handlePoll);
        } else {
            streamProcessor.poll(this::handlePoll);
        }
    }

    private List<ProducerRecord<byte[], byte[]>> handlePoll(final PollContext<byte[], byte[]> pollCtx) {
        final List<ConsumerRecord<byte[], byte[]>> records = pollCtx.getConsumerRecordsFlattened();

        final var deserializedRecords = new ArrayList<ConsumerRecord<CK, CV>>(records.size());
        for (final ConsumerRecord<byte[], byte[]> record : records) {
            try {
                deserializedRecords.add(deserialize(record));
            } catch (SerializationException e) {
                // TODO: Consider supporting error handlers, e.g. to send record to DLT.
                LOGGER.error("Failed to deserialize consumer record %s; Skipping".formatted(record), e);
            }
        }

        if (deserializedRecords.isEmpty()) {
            LOGGER.warn("All of the %d records in this batch failed to be deserialized".formatted(records.size()));
            return Collections.emptyList();
        }

        final List<ProducerRecord<PK, PV>> producerRecords;
        try {
            producerRecords = batchRecordProcessor.process(deserializedRecords);
        } catch (RetryableRecordProcessingException e) {
            LOGGER.warn("Encountered retryable exception while processing %d records".formatted(deserializedRecords.size()), e);
            throw new PCRetriableException(e);
        } catch (RecordProcessingException | RuntimeException e) {
            LOGGER.error("Encountered non-retryable exception while processing %d records; Skipping".formatted(deserializedRecords.size()), e);
            // TODO: Consider supporting error handlers, e.g. to send records to DLT.
            return Collections.emptyList(); // Skip records to avoid poison-pill scenario.
        }

        return maybeSerializeAll(producerRecords);
    }

    private static boolean canProduce(final RecordBatchProcessor<?, ?, ?, ?> processor) {
        return RecordBatchConsumer.class.isAssignableFrom(processor.getClass());
    }

}
