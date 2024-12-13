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

import com.google.protobuf.ByteString;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowPayload;
import org.jetbrains.annotations.Nullable;

public class BooleanPayloadConverter implements PayloadConverter<Boolean> {

    @Nullable
    @Override
    public WorkflowPayload convertToPayload(@Nullable final Boolean value) {
        if (value == null) {
            return null;
        }

        return WorkflowPayload.newBuilder()
                .setBinaryContent(ByteString.copyFromUtf8(String.valueOf(value)))
                .build();
    }

    @Nullable
    @Override
    public Boolean convertFromPayload(@Nullable final WorkflowPayload payload) {
        if (payload == null || !payload.hasBinaryContent()) {
            return null;
        }

        return Boolean.parseBoolean(payload.getBinaryContent().toStringUtf8());
    }

}
