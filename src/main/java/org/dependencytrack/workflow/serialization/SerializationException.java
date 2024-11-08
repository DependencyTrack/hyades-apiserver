package org.dependencytrack.workflow.serialization;

public class SerializationException extends RuntimeException {

    public SerializationException(final String message) {
        super(message);
    }

    public SerializationException(final String message, final Throwable cause) {
        super(message, cause);
    }

}
