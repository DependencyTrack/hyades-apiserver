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
package org.dependencytrack.workflow.api.payload;

import com.google.protobuf.Any;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.Message;
import org.dependencytrack.workflow.api.proto.v1.WorkflowPayload;

public class ProtobufPayloadConverter<T extends Message> implements PayloadConverter<T> {

    private final Class<T> clazz;

    public ProtobufPayloadConverter(final Class<T> clazz) {
        this.clazz = clazz;
    }

    @Override
    public WorkflowPayload convertToPayload(final T value) {
        if (value == null) {
            return null;
        }

        return WorkflowPayload.newBuilder()
                .setProtoContent(Any.pack(value))
                .build();
    }

    @Override
    public T convertFromPayload(final WorkflowPayload payload) {
        if (payload == null) {
            return null;
        }

        if (!payload.hasProtoContent()) {
            throw new PayloadConversionException("Payload has no Protobuf content");
        }

        if (!payload.getProtoContent().is(clazz)) {
            throw new PayloadConversionException(
                    "Expected Protobuf payload to be of type %s, but was %s".formatted(
                            clazz.getName(), payload.getProtoContent().getTypeUrl()));
        }

        try {
            return payload.getProtoContent().unpack(clazz);
        } catch (InvalidProtocolBufferException e) {
            throw new PayloadConversionException("Failed to convert Protobuf payload", e);
        }
    }

}