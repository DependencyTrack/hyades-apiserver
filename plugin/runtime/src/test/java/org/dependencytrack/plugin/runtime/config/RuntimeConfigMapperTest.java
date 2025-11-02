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
package org.dependencytrack.plugin.runtime.config;

import org.dependencytrack.plugin.api.config.RuntimeConfigSchemaSource;
import org.dependencytrack.plugin.api.config.RuntimeConfigSpec;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatNoException;

class RuntimeConfigMapperTest {

    private final RuntimeConfigMapper configMapper = new RuntimeConfigMapper();
    private final RuntimeConfigSpec configSpec =
            new RuntimeConfigSpec(
                    new TestRuntimeConfig(),
                    new RuntimeConfigSchemaSource.Resource("test-runtime-config.schema.json"));

    @Nested
    class SerializeTest {

        @Test
        void shouldSerializeToJson() {
            final var config = new TestRuntimeConfig()
                    .withRequiredString("foo")
                    .withEmailString("foo@example.com");

            final String configJson = configMapper.serialize(config);

            assertThatJson(configJson).isEqualTo(/* language=JSON */ """
                    {
                      "requiredString": "foo",
                      "emailString": "foo@example.com"
                    }
                    """);
        }

        @Test
        void shouldThrowWhenConfigIsNull() {
            assertThatExceptionOfType(NullPointerException.class)
                    .isThrownBy(() -> configMapper.serialize(null))
                    .withMessage("config must not be null");
        }

    }

    @Nested
    class DeserializeTest {

        @Test
        void shouldDeserializeFromJson() {
            final var config = configMapper.deserialize(/* language=JSON */ """
                            {
                              "requiredString": "foo"
                            }
                            """,
                    TestRuntimeConfig.class);

            assertThat(config).isNotNull();
            assertThat(config.getRequiredString()).isEqualTo("foo");
        }

        @Test
        void shouldThrowWhenConfigSpecIsNull() {
            assertThatExceptionOfType(NullPointerException.class)
                    .isThrownBy(() -> configMapper.deserialize((String) null, TestRuntimeConfig.class))
                    .withMessage("configJson must not be null");
        }

        @Test
        void shouldThrowWhenConfigClassIsNull() {
            assertThatExceptionOfType(NullPointerException.class)
                    .isThrownBy(() -> configMapper.deserialize("", null))
                    .withMessage("configClass must not be null");
        }

    }

    @Nested
    class ValidateTest {

        @Test
        void shouldNotThrowWhenConfigIsValid() {
            final var config = new TestRuntimeConfig()
                    .withRequiredString("foo");

            assertThatNoException()
                    .isThrownBy(() -> configMapper.validate(config, configSpec));
        }

        @Test
        void shouldThrowWhenConfigIsInvalid() {
            final var config = new TestRuntimeConfig();

            assertThatExceptionOfType(RuntimeConfigValidationException.class)
                    .isThrownBy(() -> configMapper.validate(config, configSpec));
        }

        @Test
        void shouldThrowWhenConfigIsNull() {
            assertThatExceptionOfType(NullPointerException.class)
                    .isThrownBy(() -> configMapper.validate(null, configSpec))
                    .withMessage("config must not be null");
        }

        @Test
        void shouldThrowWhenConfigSpecIsNull() {
            assertThatExceptionOfType(NullPointerException.class)
                    .isThrownBy(() -> configMapper.validate(new TestRuntimeConfig(), null))
                    .withMessage("configSpec must not be null");
        }

    }

    @Nested
    class ValidateJsonTest {

        @Test
        void shouldNotThrowWhenConfigJsonIsValid() {
            assertThatNoException()
                    .isThrownBy(() -> configMapper.validateJson(/* language=JSON */ """
                                    {
                                      "requiredString": "foo",
                                      "emailString": "foo@example.com"
                                    }
                                    """,
                            configSpec));
        }

        @Test
        void shouldThrowWhenConfigJsonIsInvalid() {
            assertThatExceptionOfType(RuntimeConfigValidationException.class)
                    .isThrownBy(() -> configMapper.validateJson(/* language=JSON */ """
                                    {
                                      "requiredString": null
                                    }
                                    """,
                            configSpec));
        }

    }


}