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
package org.dependencytrack.config.templating;

import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Deque;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

/**
 * @since 5.7.0
 */
final class ObjectGraphStringTransformer {

    private static final Logger LOGGER = LoggerFactory.getLogger(ObjectGraphStringTransformer.class);
    private static final MethodHandles.Lookup LOOKUP = MethodHandles.lookup();

    private final Map<Class<?>, List<ObjectFieldAccessor>> objectFieldCache = new ConcurrentHashMap<>();
    private final Map<Class<?>, List<StringFieldAccessor>> stringFieldCache = new ConcurrentHashMap<>();
    private final int objectTraversalLimit;
    private final int collectionSizeLimit;

    ObjectGraphStringTransformer(int objectTraversalLimit, int collectionSizeLimit) {
        this.objectTraversalLimit = objectTraversalLimit;
        this.collectionSizeLimit = collectionSizeLimit;
    }

    void transform(
            final Object root,
            final Function<String, @Nullable String> transformation) throws Throwable {
        final var visited = Collections.newSetFromMap(new IdentityHashMap<>());
        final var queue = new ArrayDeque<>();
        var objectCount = 0;

        queue.add(root);
        visited.add(root);

        while (!queue.isEmpty()) {
            if (++objectCount > objectTraversalLimit) {
                throw new IllegalStateException(
                        "Limit of %d object traversals exceeded".formatted(objectTraversalLimit));
            }

            final Object current = queue.pop();
            if (current != null && shouldTraverse(current.getClass())) {
                transformStringFields(current, transformation);
                queueNestedObjects(current, queue, visited);
            }
        }
    }

    private void transformStringFields(
            final Object object,
            final Function<String, String> transformation) throws Throwable {
        final List<StringFieldAccessor> accessors = getStringFieldAccessors(object.getClass());

        for (final StringFieldAccessor accessor : accessors) {
            final String value = accessor.getValue(object);
            if (value != null) {
                final String transformed = transformation.apply(value);
                if (!Objects.equals(value, transformed)) {
                    accessor.setValue(object, transformed);
                }
            }
        }
    }

    private void queueNestedObjects(
            final Object object,
            final Deque<Object> queue,
            final Set<Object> visited) throws Throwable {
        final Class<?> clazz = object.getClass();

        if (object instanceof final Collection<?> collection) {
            if (collection.size() > collectionSizeLimit) {
                throw new IllegalStateException(
                        "Collection of size %d exceeds size limit of %d".formatted(
                                collection.size(), collectionSizeLimit));
            }

            for (final Object element : collection) {
                if (element != null && !visited.contains(element)) {
                    queue.add(element);
                    visited.add(element);
                }
            }
        } else if (object instanceof final Map<?, ?> map) {
            if (map.size() > collectionSizeLimit) {
                throw new IllegalStateException(
                        "Map of size %d exceeds collection size limit of %d".formatted(
                                map.size(), collectionSizeLimit));
            }

            for (final Object value : map.values()) {
                if (value != null && !visited.contains(value)) {
                    queue.add(value);
                    visited.add(value);
                }
            }
        } else {
            final List<ObjectFieldAccessor> accessors = getObjectFieldAccessors(clazz);

            for (final ObjectFieldAccessor accessor : accessors) {
                final Object fieldValue = accessor.getValue(object);
                if (fieldValue != null
                        && !visited.contains(fieldValue)
                        && shouldTraverse(fieldValue.getClass())) {
                    queue.add(fieldValue);
                    visited.add(fieldValue);
                }
            }
        }
    }

    private List<ObjectFieldAccessor> getObjectFieldAccessors(final Class<?> clazz) {
        return objectFieldCache.computeIfAbsent(clazz, this::collectObjectFieldAccessors);
    }

    private List<StringFieldAccessor> getStringFieldAccessors(final Class<?> clazz) {
        return stringFieldCache.computeIfAbsent(clazz, this::collectStringFieldAccessors);
    }

    private List<ObjectFieldAccessor> collectObjectFieldAccessors(final Class<?> clazz) {
        final var accessors = new ArrayList<ObjectFieldAccessor>();

        Class<?> currentClass = clazz;
        while (currentClass != null && currentClass != Object.class) {
            for (final Field field : currentClass.getDeclaredFields()) {
                if (Modifier.isStatic(field.getModifiers())
                        || Modifier.isFinal(field.getModifiers())
                        || field.getType().isPrimitive()) {
                    continue;
                }

                try {
                    accessors.add(ObjectFieldAccessor.of(field));
                } catch (IllegalAccessException e) {
                    LOGGER.debug(
                            "Failed to create accessor for field {}#{}",
                            currentClass.getName(),
                            field.getName(),
                            e);
                }
            }

            currentClass = currentClass.getSuperclass();
        }

        return accessors;
    }

    private List<StringFieldAccessor> collectStringFieldAccessors(final Class<?> clazz) {
        final var accessors = new ArrayList<StringFieldAccessor>();

        Class<?> currentClass = clazz;
        while (currentClass != null && currentClass != Object.class) {
            for (final Field field : currentClass.getDeclaredFields()) {
                if (Modifier.isStatic(field.getModifiers())
                        || Modifier.isFinal(field.getModifiers())
                        || field.getType() != String.class) {
                    continue;
                }

                try {
                    accessors.add(StringFieldAccessor.of(field));
                } catch (IllegalAccessException e) {
                    LOGGER.debug(
                            "Failed to create accessor for string field {}#{}",
                            currentClass.getName(),
                            field.getName(),
                            e);
                }
            }

            currentClass = currentClass.getSuperclass();
        }

        return accessors;
    }

    private boolean shouldTraverse(final Class<?> clazz) {
        if (clazz.isPrimitive() || clazz.isEnum()) {
            return false;
        }

        final String className = clazz.getName();
        return !className.startsWith("java.lang.")
                && !className.startsWith("java.time.")
                && !className.startsWith("java.math.")
                && !className.startsWith("java.util.UUID")
                && !className.startsWith("java.net.");
    }

    private record ObjectFieldAccessor(MethodHandle getter) {

        static ObjectFieldAccessor of(final Field field) throws IllegalAccessException {
            field.setAccessible(true);

            return new ObjectFieldAccessor(LOOKUP.unreflectGetter(field));
        }

        private @Nullable Object getValue(final Object instance) throws Throwable {
            return getter.invoke(instance);
        }

    }

    private record StringFieldAccessor(MethodHandle getter, MethodHandle setter) {

        static StringFieldAccessor of(final Field field) throws IllegalAccessException {
            field.setAccessible(true);

            return new StringFieldAccessor(
                    LOOKUP.unreflectGetter(field),
                    LOOKUP.unreflectSetter(field));
        }

        private @Nullable String getValue(final Object instance) throws Throwable {
            return (String) getter.invoke(instance);
        }

        private void setValue(final Object instance, final String value) throws Throwable {
            setter.invoke(instance, value);
        }

    }

}
