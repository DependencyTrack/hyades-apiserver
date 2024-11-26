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
package org.dependencytrack.resources.v1.serializers;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import com.google.protobuf.util.JsonFormat;
import org.dependencytrack.proto.workflow.payload.v1alpha1.Payload;
import org.dependencytrack.proto.workflow.v1alpha1.Workflow;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowEvent;

import java.io.IOException;

public class WorkflowEventJsonSerializer extends StdSerializer<WorkflowEvent> {

    public WorkflowEventJsonSerializer() {
        super(WorkflowEvent.class);
    }

    @Override
    public void serialize(
            final WorkflowEvent value,
            final JsonGenerator jsonGenerator,
            final SerializerProvider serializerProvider) throws IOException {
        jsonGenerator.writeRawValue(JsonFormat.printer()
                .omittingInsignificantWhitespace()
                .usingTypeRegistry(JsonFormat.TypeRegistry.newBuilder()
                        .add(Workflow.getDescriptor().getMessageTypes())
                        .add(Payload.getDescriptor().getMessageTypes())
                        .build())
                .print(value));
    }

}
