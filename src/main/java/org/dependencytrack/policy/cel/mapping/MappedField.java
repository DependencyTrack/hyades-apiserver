package org.dependencytrack.policy.cel.mapping;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.FIELD)
public @interface MappedField {

    /**
     * Name of the field in the Protobuf schema.
     * <p>
     * If empty string (the default), the name of the annotated field will be assumed.
     *
     * @return Name of the Protobuf field
     */
    String protoFieldName() default "";

    /**
     * Name of the SQL column corresponding to this field.
     *
     * @return Name of the SQL column
     */
    String sqlColumnName();

}
