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
import org.dependencytrack.common.pagination.InvalidPageTokenException;
import org.dependencytrack.common.pagination.PageToken;
import org.dependencytrack.common.pagination.PageTokenEncoder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

public class EncryptedPageTokenEncoderTest {

    private static PageTokenEncoder encoder;

    @BeforeAll
    public static void beforeEach() {
        encoder = new EncryptedPageTokenEncoder(new DataEncryption());
    }

    @Test
    public void shouldDecodeEncodedToken() {
        final var pageToken = new TestPageToken("foo");

        final String encodedToken = encoder.encode(pageToken);

        final var decodedToken = encoder.decode(encodedToken, TestPageToken.class);

        assertThat(decodedToken).isEqualTo(pageToken);
    }

    @Test
    public void decodeShouldThrowWhenEncodedTokenIsNotBase64Encoded() {
        final var encodedToken = "notBase64!";

        assertThatExceptionOfType(InvalidPageTokenException.class)
                .isThrownBy(() -> encoder.decode(encodedToken, TestPageToken.class));
    }

    @Test
    public void decodeShouldThrowWhenPageTokenCanNotBeDecrypted() {
        final var encodedToken = Base64.getEncoder().encodeToString("invalid".getBytes());

        assertThatExceptionOfType(InvalidPageTokenException.class)
                .isThrownBy(() -> encoder.decode(encodedToken, TestPageToken.class));
    }

    public record TestPageToken(String value) implements PageToken {
    }

}