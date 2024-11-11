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
import com.google.protobuf.ByteString;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowPayload;

import java.io.IOException;
import java.util.Optional;

public class JsonPayloadConverter<T> implements PayloadConverter<T> {

    private final JsonMapper jsonMapper;
    private final Class<T> clazz;

    JsonPayloadConverter(final JsonMapper jsonMapper, final Class<T> clazz) {
        this.jsonMapper = jsonMapper;
        this.clazz = clazz;
    }

    @Override
    public Optional<WorkflowPayload> convertToPayload(final T value) {
        if (value == null) {
            return Optional.empty();
        }

        final byte[] serializedValue;
        try {
            serializedValue = jsonMapper.writeValueAsBytes(value);
        } catch (IOException e) {
            throw new PayloadConversionException("Failed to serialize value to JSON", e);
        }

        return Optional.of(WorkflowPayload.newBuilder()
                .setBinaryContent(ByteString.copyFrom(serializedValue))
                .build());
    }

    @Override
    public Optional<T> convertFromPayload(final WorkflowPayload payload) {
        if (payload == null) {
            return Optional.empty();
        }

        if (!payload.hasBinaryContent()) {
            throw new PayloadConversionException("Payload has no binary content");
        }

        try {
            return Optional.of(jsonMapper.readValue(payload.getBinaryContent().toByteArray(), clazz));
        } catch (IOException e) {
            throw new PayloadConversionException("Failed to deserialize value from JSON", e);
        }
    }

}
