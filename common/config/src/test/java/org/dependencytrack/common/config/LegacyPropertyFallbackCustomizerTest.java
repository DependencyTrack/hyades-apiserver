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
package org.dependencytrack.common.config;

import io.smallrye.config.SmallRyeConfigBuilder;
import org.eclipse.microprofile.config.Config;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class LegacyPropertyFallbackCustomizerTest {

    @Test
    void shouldFallBackToAlpinePrefixForKnownAlpineProperties() {
        final Config config = buildConfig(Map.of("alpine.ldap.enabled", "true"));

        assertThat(config.getOptionalValue("dt.ldap.enabled", String.class))
                .contains("true");
    }

    @Test
    void shouldFallBackToUnprefixedNameForNonAlpineProperties() {
        final Config config = buildConfig(Map.of("vulnerability.policy.bundle.url", "http://example.com"));

        assertThat(config.getOptionalValue("dt.vulnerability.policy.bundle.url", String.class))
                .contains("http://example.com");
    }

    @Test
    void shouldPreferCanonicalNameOverFallback() {
        final Config config = buildConfig(Map.of(
                "dt.ldap.enabled", "canonical",
                "alpine.ldap.enabled", "fallback"));

        assertThat(config.getOptionalValue("dt.ldap.enabled", String.class))
                .contains("canonical");
    }

    @Test
    void shouldNotFallBackForNonDtProperties() {
        final Config config = buildConfig(Map.of("some.other.property", "value"));

        assertThat(config.getOptionalValue("some.other.property", String.class))
                .contains("value");
        assertThat(config.getOptionalValue("dt.unrelated", String.class))
                .isNotPresent();
    }

    @Test
    void shouldHandleProfilePrefixForAlpineProperties() {
        final Config config = buildConfig(Map.of("%dev.alpine.database.url", "jdbc:h2:mem:dev"));

        assertThat(config.getOptionalValue("%dev.dt.database.url", String.class))
                .contains("jdbc:h2:mem:dev");
    }

    @Test
    void shouldHandleProfilePrefixForNonAlpineProperties() {
        final Config config = buildConfig(Map.of("%test.task.foo.cron", "0 0 * * *"));

        assertThat(config.getOptionalValue("%test.dt.task.foo.cron", String.class))
                .contains("0 0 * * *");
    }

    @Test
    void shouldReturnEmptyWhenNoFallbackExists() {
        final Config config = buildConfig(Map.of());

        assertThat(config.getOptionalValue("dt.nonexistent.property", String.class))
                .isNotPresent();
    }

    private static Config buildConfig(Map<String, String> properties) {
        final var builder = new SmallRyeConfigBuilder()
                .withDefaultValues(properties)
                .withCustomizers(new LegacyPropertyFallbackCustomizer());
        return builder.build();
    }

}
