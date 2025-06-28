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
package org.dependencytrack.parser.spdx.json;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;

/**
 * This class parses json metadata file that describe each license. It does not
 * parse SPDX files themselves. License data is obtained from:
 * <p>
 * https://github.com/spdx/license-list-data
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public class SpdxLicenseDetailsParser {

    private final ObjectMapper objectMapper = new ObjectMapper()
            .enable(JsonParser.Feature.AUTO_CLOSE_SOURCE);

    public Iterator<SpdxLicenseDetails> getLicenseDetails() {
        final InputStream licensesInputStream = getClass().getResourceAsStream("/spdx-license-list.json");

        final JsonParser jsonParser;
        try {
            jsonParser = objectMapper.createParser(licensesInputStream);
            jsonParser.nextToken(); // Position cursor at first token
        } catch (IOException e) {
            throw new IllegalStateException("Failed to initialize JSON parser", e);
        }

        return new LicenseDetailsIterator(jsonParser);
    }

    private static class LicenseDetailsIterator implements Iterator<SpdxLicenseDetails> {

        private final JsonParser jsonParser;

        private LicenseDetailsIterator(final JsonParser jsonParser) {
            this.jsonParser = jsonParser;
        }

        @Override
        public boolean hasNext() {
            if (jsonParser.isClosed()) {
                return false;
            }

            try {
                final JsonToken currentToken = jsonParser.nextToken();
                if (currentToken != JsonToken.START_OBJECT) {
                    jsonParser.close();
                    return false;
                }
            } catch (IOException e) {
                throw new IllegalStateException("Failed to read next JSON token", e);
            }

            return true;
        }

        @Override
        public SpdxLicenseDetails next() {
            try {
                return jsonParser.readValueAs(SpdxLicenseDetails.class);
            } catch (IOException e) {
                throw new IllegalStateException("Failed to read license details", e);
            }
        }

    }

}
