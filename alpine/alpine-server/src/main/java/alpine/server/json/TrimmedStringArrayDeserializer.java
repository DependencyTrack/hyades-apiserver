/*
 * This file is part of Alpine.
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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package alpine.server.json;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import io.jsonwebtoken.lang.Collections;
import org.apache.commons.lang3.StringUtils;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * This custom deserializer ensures that empty strings are deserialized as null rather than an "".
 *
 * Usage example:
 * <pre>
 * &#64;JsonDeserialize(using = TrimmedStringArrayDeserializer.class)
 * String name;
 * </pre>
 *
 * @author Steve Springett
 * @since 1.0.0
 */
public class TrimmedStringArrayDeserializer extends JsonDeserializer<String[]> {

    @Override
    public String[] deserialize(JsonParser jsonParser, DeserializationContext context) throws IOException {
        final List<String> list = new ArrayList<>();
        final JsonNode node = jsonParser.readValueAsTree();
        if (node.isArray()) {
            final Iterator elements = node.elements();
            while (elements.hasNext()) {
                final JsonNode childNode = (JsonNode) elements.next();
                final String value = StringUtils.trimToNull(childNode.asText());
                if (value != null) {
                    list.add(value);
                }
            }
        }
        if (Collections.isEmpty(list)) {
            return null;
        } else {
            return list.toArray(new String[list.size()]);
        }
    }

}
