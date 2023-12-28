package org.dependencytrack.event.kafka.processor.exception;

/**
 * A {@link RecordProcessingException} indicating a retryable error.
 */
public class RetryableRecordProcessingException extends RecordProcessingException {

    /**
     * {@inheritDoc}
     */
    public RetryableRecordProcessingException(final String message) {
        super(message);
    }

    /**
     * {@inheritDoc}
     */
    public RetryableRecordProcessingException(final String message, final Throwable cause) {
        super(message, cause);
    }

    /**
     * {@inheritDoc}
     */
    public RetryableRecordProcessingException(final Throwable cause) {
        super(cause);
    }

}
