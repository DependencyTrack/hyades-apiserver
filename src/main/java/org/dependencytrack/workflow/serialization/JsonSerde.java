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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.json.JsonMapper;

import java.io.IOException;

public class JsonSerde<T> implements Serde<T> {

    private final JsonMapper jsonMapper;

    private final Class<T> clazz;

    JsonSerde(final Class<T> clazz, final JsonMapper jsonMapper) {
        this.clazz = clazz;
        this.jsonMapper = jsonMapper;
    }

    public JsonSerde(final Class<T> clazz) {
        this(clazz, new JsonMapper());
    }

    @Override
    public byte[] serialize(final T value) {
        if (value == null) {
            return null;
        }

        try {
            return jsonMapper.writeValueAsBytes(value);
        } catch (JsonProcessingException e) {
            throw new SerializationException(e);
        }
    }

    @Override
    public T deserialize(final byte[] bytes) {
        if (bytes == null) {
            return null;
        }

        try {
            return jsonMapper.readValue(bytes, clazz);
        } catch (IOException e) {
            throw new SerializationException(e);
        }
    }

}
