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
package org.dependencytrack.workflow.engine.payload;

import com.google.protobuf.ByteString;
import org.dependencytrack.workflow.api.payload.PayloadConversionException;
import org.dependencytrack.workflow.api.payload.PayloadConverter;
import org.dependencytrack.workflow.api.proto.v1.WorkflowPayload;
import org.dependencytrack.workflow.api.proto.v1.WorkflowPayload.BinaryContent;

public class StringPayloadConverter implements PayloadConverter<String> {

    private static final String MEDIA_TYPE = "text/plain";

    @Override
    public WorkflowPayload convertToPayload(final String value) {
        if (value == null) {
            return null;
        }

        return WorkflowPayload.newBuilder()
                .setBinaryContent(BinaryContent.newBuilder()
                        .setMediaType(MEDIA_TYPE)
                        .setData(ByteString.copyFromUtf8(value))
                        .build())
                .build();
    }

    @Override
    public String convertFromPayload(final WorkflowPayload payload) {
        if (payload == null || !payload.hasBinaryContent()) {
            return null;
        }

        final BinaryContent binaryContent = payload.getBinaryContent();
        if (!MEDIA_TYPE.equals(binaryContent.getMediaType())) {
            throw new PayloadConversionException(
                    "Expected binary content of type %s, but got %s".formatted(
                            MEDIA_TYPE, binaryContent.getMediaType()));
        }

        return payload.getBinaryContent().getData().toStringUtf8();
    }

}
