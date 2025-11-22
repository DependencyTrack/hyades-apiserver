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
package org.dependencytrack.common;

import alpine.security.crypto.DataEncryption;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.dependencytrack.common.pagination.InvalidPageTokenException;
import org.dependencytrack.common.pagination.PageToken;
import org.dependencytrack.common.pagination.PageTokenEncoder;

import java.util.Base64;

/**
 * A {@link PageTokenEncoder} that encrypts page tokens to prevent tampering.
 *
 * @since 5.7.0
 */
public final class EncryptedPageTokenEncoder implements PageTokenEncoder {

    private final ObjectMapper objectMapper;
    private final DataEncryption dataEncryption;

    EncryptedPageTokenEncoder(DataEncryption dataEncryption) {
        this.objectMapper = new ObjectMapper();
        this.dataEncryption = dataEncryption;
    }

    public EncryptedPageTokenEncoder() {
        this(new DataEncryption());
    }

    @Override
    public String encode(PageToken pageToken) {
        if (pageToken == null) {
            return null;
        }

        try {
            final String tokenJson = objectMapper.writeValueAsString(pageToken);
            final byte[] encryptedTokenBytes = dataEncryption.encryptAsBytes(tokenJson);
            return Base64.getUrlEncoder().encodeToString(encryptedTokenBytes);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public <T extends PageToken> T decode(String encoded, Class<T> pageTokenClass) {
        if (encoded == null) {
            return null;
        }

        try {
            final byte[] encryptedTokenBytes = Base64.getUrlDecoder().decode(encoded);
            final byte[] decryptedToken = dataEncryption.decryptAsBytes(encryptedTokenBytes);
            return objectMapper.readValue(decryptedToken, pageTokenClass);
        } catch (Exception e) {
            throw new InvalidPageTokenException(e);
        }
    }

}
