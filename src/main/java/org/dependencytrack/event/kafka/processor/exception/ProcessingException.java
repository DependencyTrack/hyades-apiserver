package org.dependencytrack.event.kafka.processor.exception;

/**
 * An {@link Exception} indicating an error during record processing.
 */
public class ProcessingException extends Exception {

    /**
     * {@inheritDoc}
     */
    public ProcessingException(final String message) {
        super(message);
    }

    /**
     * {@inheritDoc}
     */
    public ProcessingException(final String message, final Throwable cause) {
        super(message, cause);
    }

    /**
     * {@inheritDoc}
     */
    public ProcessingException(final Throwable cause) {
        super(cause);
    }

}