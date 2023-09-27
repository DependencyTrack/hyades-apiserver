package org.dependencytrack.policy.cel.mapping;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import static org.apache.commons.lang3.StringUtils.trimToNull;

public final class FieldMappingUtil {

    private static final Map<Class<?>, List<FieldMapping>> FIELD_MAPPINGS_BY_CLASS = new ConcurrentHashMap<>();

    private FieldMappingUtil() {
    }

    public static List<FieldMapping> getFieldMappings(final Class<?> clazz) {
        return FIELD_MAPPINGS_BY_CLASS.computeIfAbsent(clazz, FieldMappingUtil::createFieldMappings);
    }

    private static List<FieldMapping> createFieldMappings(final Class<?> clazz) {
        final var fieldMappings = new ArrayList<FieldMapping>();

        for (final Field field : clazz.getDeclaredFields()) {
            final MappedField mappedFieldAnnotation = field.getAnnotation(MappedField.class);
            if (mappedFieldAnnotation == null) {
                continue;
            }

            final String javaFieldName = field.getName();
            final String protoFieldName = Optional.ofNullable(trimToNull(mappedFieldAnnotation.protoFieldName())).orElse(javaFieldName);
            final String sqlColumnName = Optional.ofNullable(trimToNull(mappedFieldAnnotation.sqlColumnName())).orElseThrow();
            fieldMappings.add(new FieldMapping(javaFieldName, protoFieldName, sqlColumnName));
        }

        return fieldMappings;
    }

}
