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

import java.util.Collections;
import java.util.List;

/**
 * A {@link RecordProcessingStrategy} that processes records individually.
 *
 * @param <CK> Type of the {@link ConsumerRecord} key
 * @param <CV> Type of the {@link ConsumerRecord} value
 * @param <PK> Type of the {@link ProducerRecord} key
 * @param <PV> Type of the {@link ProducerRecord} value
 */
public class SingleRecordProcessingStrategy<CK, CV, PK, PV> extends AbstractRecordProcessingStrategy<CK, CV, PK, PV> {

    private static final Logger LOGGER = Logger.getLogger(SingleRecordProcessingStrategy.class);

    private final RecordProcessor<CK, CV, PK, PV> recordProcessor;

    public SingleRecordProcessingStrategy(final RecordProcessor<CK, CV, PK, PV> recordProcessor,
                                          final Deserializer<CK> keyDeserializer, final Deserializer<CV> valueDeserializer,
                                          final Serializer<PK> keySerializer, final Serializer<PV> valueSerializer) {
        super(keyDeserializer, valueDeserializer, keySerializer, valueSerializer);
        this.recordProcessor = recordProcessor;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void process(final ParallelStreamProcessor<byte[], byte[]> streamProcessor) {
        if (canProduce(recordProcessor)) {
            streamProcessor.pollAndProduceMany(this::handlePoll);
        } else {
            streamProcessor.poll(this::handlePoll);
        }
    }

    private List<ProducerRecord<byte[], byte[]>> handlePoll(final PollContext<byte[], byte[]> pollCtx) {
        final ConsumerRecord<byte[], byte[]> record = pollCtx.getSingleConsumerRecord();

        final ConsumerRecord<CK, CV> deserializedRecord;
        try {
            deserializedRecord = deserialize(record);
        } catch (SerializationException e) {
            LOGGER.error("Failed to deserialize consumer record %s; Skipping".formatted(record), e);
            // TODO: Consider supporting error handlers, e.g. to send record to DLT.
            return Collections.emptyList(); // Skip record to avoid poison-pill scenario.
        }

        final List<ProducerRecord<PK, PV>> producerRecords;
        try {
            producerRecords = recordProcessor.process(deserializedRecord);
        } catch (RetryableRecordProcessingException e) {
            LOGGER.warn("Encountered retryable exception while processing %s".formatted(deserializedRecord), e);
            throw new PCRetriableException(e);
        } catch (RecordProcessingException | RuntimeException e) {
            LOGGER.error("Encountered non-retryable exception while processing %s; Skipping".formatted(deserializedRecord), e);
            // TODO: Consider supporting error handlers, e.g. to send record to DLT.
            return Collections.emptyList(); // Skip record to avoid poison-pill scenario.
        }

        return maybeSerializeAll(producerRecords);
    }

    private static boolean canProduce(final RecordProcessor<?, ?, ?, ?> processor) {
        return !RecordConsumer.class.isAssignableFrom(processor.getClass());
    }

}
