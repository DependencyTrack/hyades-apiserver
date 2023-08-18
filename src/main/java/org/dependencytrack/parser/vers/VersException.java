package org.dependencytrack.parser.vers;

public class VersException extends RuntimeException {

    VersException(final String message) {
        this(message, null);
    }

    VersException(final String message, final Throwable cause) {
        super(message, cause);
    }

}