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
package org.dependencytrack.workflow.serialization;

import com.fasterxml.jackson.databind.json.JsonMapper;
import com.google.common.base.Supplier;
import com.google.common.base.Suppliers;
import com.google.protobuf.Message;
import com.google.protobuf.Parser;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public final class Serdes {

    private static final Supplier<JsonMapper> JSON_MAPPER_SUPPLIER = Suppliers.memoize(JsonMapper::new);
    private static final Map<Class<?>, JsonSerde<?>> JSON_SERDES = new ConcurrentHashMap<>(1);
    private static final Map<Class<?>, ProtobufSerde<?>> PROTOBUF_SERDES = new ConcurrentHashMap<>(1);
    private static final Serde<Void> VOID_SERDE = new VoidSerde();

    private Serdes() {
    }

    @SuppressWarnings("unchecked")
    public static <T> JsonSerde<T> jsonSerde(final Class<T> clazz) {
        final JsonMapper jsonMapper = JSON_MAPPER_SUPPLIER.get();
        return (JsonSerde<T>) JSON_SERDES.computeIfAbsent(
                clazz, ignored -> new JsonSerde<>(clazz, jsonMapper));
    }

    @SuppressWarnings("unchecked")
    public static <T extends Message> ProtobufSerde<T> protobufSerde(final Class<T> clazz) {
        return (ProtobufSerde<T>) PROTOBUF_SERDES.computeIfAbsent(clazz, ignored -> {
            try {
                final Method parserMethod = clazz.getMethod("parser");
                final var parser = (Parser<T>) parserMethod.invoke(null);
                return new ProtobufSerde<>(parser);
            } catch (NoSuchMethodException | IllegalAccessException | InvocationTargetException e) {
                throw new RuntimeException("Failed to instantiate Protobuf parser", e);
            }
        });
    }

    public static Serde<Void> voidSerde() {
        return VOID_SERDE;
    }

}
