package org.dependencytrack.event.kafka.processor.exception;

/**
 * A {@link ProcessingException} indicating a retryable error.
 */
public class RetryableProcessingException extends ProcessingException {

    /**
     * {@inheritDoc}
     */
    public RetryableProcessingException(final String message) {
        super(message);
    }

    /**
     * {@inheritDoc}
     */
    public RetryableProcessingException(final String message, final Throwable cause) {
        super(message, cause);
    }

    /**
     * {@inheritDoc}
     */
    public RetryableProcessingException(final Throwable cause) {
        super(cause);
    }

}
