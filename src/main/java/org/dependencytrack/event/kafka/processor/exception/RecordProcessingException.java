package org.dependencytrack.event.kafka.processor.exception;

/**
 * An {@link Exception} indicating an error during record processing.
 */
public class RecordProcessingException extends Exception {

    /**
     * {@inheritDoc}
     */
    public RecordProcessingException(final String message) {
        super(message);
    }

    /**
     * {@inheritDoc}
     */
    public RecordProcessingException(final String message, final Throwable cause) {
        super(message, cause);
    }

    /**
     * {@inheritDoc}
     */
    public RecordProcessingException(final Throwable cause) {
        super(cause);
    }

}
