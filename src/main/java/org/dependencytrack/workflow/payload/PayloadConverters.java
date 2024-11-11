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
package org.dependencytrack.workflow.payload;

import com.fasterxml.jackson.databind.json.JsonMapper;
import com.google.common.base.Supplier;
import com.google.common.base.Suppliers;
import com.google.protobuf.Message;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public final class PayloadConverters {

    private static final Supplier<JsonMapper> JSON_MAPPER_SUPPLIER = Suppliers.memoize(JsonMapper::new);
    private static final Map<Class<?>, JsonPayloadConverter<?>> JSON_CONVERTERS = new ConcurrentHashMap<>(1);
    private static final Map<Class<?>, ProtobufPayloadConverter<?>> PROTO_CONVERTERS = new ConcurrentHashMap<>(1);
    private static final VoidPayloadConverter VOID_CONVERTER = new VoidPayloadConverter();

    private PayloadConverters() {
    }

    @SuppressWarnings("unchecked")
    public static <T> PayloadConverter<T> jsonConverter(final Class<T> clazz) {
        final JsonMapper jsonMapper = JSON_MAPPER_SUPPLIER.get();
        return (PayloadConverter<T>) JSON_CONVERTERS.computeIfAbsent(
                clazz, ignored -> new JsonPayloadConverter<>(jsonMapper, clazz));
    }

    @SuppressWarnings("unchecked")
    public static <T extends Message> ProtobufPayloadConverter<T> protobufConverter(final Class<T> clazz) {
        return (ProtobufPayloadConverter<T>) PROTO_CONVERTERS.computeIfAbsent(clazz,
                ignored -> new ProtobufPayloadConverter<>(clazz));
    }

    public static VoidPayloadConverter voidConverter() {
        return VOID_CONVERTER;
    }

}
