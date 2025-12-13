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
package org.dependencytrack.common.pagination;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.util.Base64;

/**
 * @since 5.7.0
 */
public final class SimplePageTokenEncoder implements PageTokenEncoder {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public @Nullable String encode(@Nullable PageToken pageToken) {
        if (pageToken == null) {
            return null;
        }

        try {
            final String pageTokenJson = objectMapper.writeValueAsString(pageToken);
            return Base64.getUrlEncoder().encodeToString(pageTokenJson.getBytes());
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public <T extends PageToken> @Nullable T decode(@Nullable String encoded, Class<T> pageTokenClass) {
        if (encoded == null) {
            return null;
        }

        try {
            final byte[] pageTokenJson = Base64.getUrlDecoder().decode(encoded);
            return objectMapper.readValue(pageTokenJson, pageTokenClass);
        } catch (IOException e) {
            throw new InvalidPageTokenException(e);
        }
    }

}
