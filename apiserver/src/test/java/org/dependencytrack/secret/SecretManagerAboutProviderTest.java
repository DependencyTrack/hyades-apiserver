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
package org.dependencytrack.secret;

import org.dependencytrack.secret.management.SecretManager;
import org.junit.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

public class SecretManagerAboutProviderTest {

    @Test
    public void shouldProvideNameAndReadOnlyStatus() {
        final var secretManagerMock = mock(SecretManager.class);
        doReturn("foo").when(secretManagerMock).name();
        doReturn(true).when(secretManagerMock).isReadOnly();

        final var aboutProvider = new SecretManagerAboutProvider(() -> secretManagerMock);

        final Map<String, Object> aboutData = aboutProvider.collect();
        assertThat(aboutData).containsExactlyInAnyOrderEntriesOf(
                Map.ofEntries(
                        Map.entry("provider", "foo"),
                        Map.entry("readOnly", true)));
    }

}