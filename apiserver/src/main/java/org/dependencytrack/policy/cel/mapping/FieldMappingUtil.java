/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
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
