package org.dependencytrack.workflow.payload;

public class PayloadConverters {

    public static PayloadConverter<String> stringConverter() {
        return new StringPayloadConverter();
    }

    public static PayloadConverter<Void> voidConverter() {
        return new VoidPayloadConverter();
    }

}
