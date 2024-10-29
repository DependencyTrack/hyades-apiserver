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
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;

import java.io.IOException;
import java.util.List;

import org.dependencytrack.model.Ikev2Type;

/**
 * Custom serializer which takes in a List of CryptoFunction IDs (String) serializes them into an JSON array of String objects.
 * @since 5.6.0
 */
public class Ikev2TypesSerializer extends JsonSerializer<List<Ikev2Type>> {

    @Override
    public void serialize(List<Ikev2Type> ikev2Types, JsonGenerator jsonGenerator, SerializerProvider serializerProvider)
            throws IOException, JsonProcessingException {

        jsonGenerator.writeStartObject();
        for (final Ikev2Type ik: ikev2Types) {
            jsonGenerator.writeFieldName(ik.getType());
            String[] refs = new String[ik.getRefs().size()];
            ik.getRefs().toArray(refs);
            jsonGenerator.writeArray(refs, 0, ik.getRefs().size());
        }
        jsonGenerator.writeEndObject();
    }
}
