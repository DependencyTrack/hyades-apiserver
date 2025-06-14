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
package org.dependencytrack.workflow.engine.persistence.pagination;

import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.Message;
import com.google.protobuf.Parser;
import org.jspecify.annotations.Nullable;

import java.util.Base64;

public final class PageTokenUtil {

    @Nullable
    public static <T extends Message> String encodePageToken(@Nullable final T token) {
        if (token == null) {
            return null;
        }

        final byte[] tokenBytes = token.toByteArray();
        return Base64.getUrlEncoder().encodeToString(tokenBytes);
    }

    @Nullable
    public static <T extends Message> T decodePageToken(@Nullable final String token, final Parser<T> parser) {
        if (token == null || token.isBlank()) {
            return null;
        }

        try {
            final byte[] tokenBytes = Base64.getUrlDecoder().decode(token);
            return parser.parseFrom(tokenBytes);
        } catch (IllegalArgumentException | InvalidProtocolBufferException e) {
            throw new InvalidPageTokenException(e);
        }
    }

}
