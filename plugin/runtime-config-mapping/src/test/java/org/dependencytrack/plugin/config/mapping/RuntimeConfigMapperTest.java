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
package org.dependencytrack.plugin.config.mapping;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotNull;
import net.javacrumbs.jsonunit.core.Option;
import org.dependencytrack.plugin.api.config.RuntimeConfig;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatNoException;

class RuntimeConfigMapperTest {

    private final RuntimeConfigMapper configMapper = new RuntimeConfigMapper();

    @Nested
    class SerializeTest {

        @Test
        void shouldSerializeToYaml() {
            final var config = new TestConfig();
            config.setJacksonRequiredString("foo");
            config.setJvEmailString("foo@example.com");

            final String configYaml = configMapper.serialize(config);

            assertThat(configYaml).isEqualTo(/* language=YAML */ """
                    ---
                    jacksonRequiredString: "foo"
                    jvEmailString: "foo@example.com"
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
        void shouldDeserializeFromYaml() {
            final var config = configMapper.deserialize(/* language=YAML */ """
                    ---
                    jacksonRequiredString: "foo"
                    """, TestConfig.class);

            assertThat(config).isNotNull();
            assertThat(config.getJacksonRequiredString()).isEqualTo("foo");
        }

        @Test
        void shouldThrowWhenConfigYamlIsNull() {
            assertThatExceptionOfType(NullPointerException.class)
                    .isThrownBy(() -> configMapper.deserialize(null, TestConfig.class))
                    .withMessage("configYaml must not be null");
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
            final var config = new TestConfig();
            config.setJacksonRequiredString("foo");
            config.setJvRequiredString("bar");
            config.setSwaggerRequiredString("baz");

            assertThatNoException()
                    .isThrownBy(() -> configMapper.validate(config));
        }

        @Test
        void shouldThrowWhenConfigIsInvalid() {
            final var config = new TestConfig();

            assertThatExceptionOfType(RuntimeConfigValidationException.class)
                    .isThrownBy(() -> configMapper.validate(config));
        }

        @Test
        void shouldThrowWhenConfigIsNull() {
            assertThatExceptionOfType(NullPointerException.class)
                    .isThrownBy(() -> configMapper.validate(null))
                    .withMessage("config must not be null");
        }

    }

    @Nested
    class ValidateYamlTest {

        @Test
        void shouldNotThrowWhenConfigYamlIsValid() {
            assertThatNoException()
                    .isThrownBy(() -> configMapper.validateYaml(/* language=YAML */ """
                            jacksonRequiredString: "foo"
                            jvRequiredString: "bar"
                            swaggerRequiredString: "baz"
                            """, TestConfig.class));
        }

        @Test
        void shouldThrowWhenConfigYamlIsInvalid() {
            assertThatExceptionOfType(RuntimeConfigValidationException.class)
                    .isThrownBy(() -> configMapper.validateYaml(/* language=YAML */ """
                            jacksonRequiredString: null
                            """, TestConfig.class));
        }

    }

    @Nested
    class GetSchemaTest {

        @Test
        void shouldReturnJsonSchema() {
            final String schemaJson = configMapper.getJsonSchema(TestConfig.class);
            assertThatJson(schemaJson)
                    .withOptions(Option.IGNORING_ARRAY_ORDER)
                    .isEqualTo(/* language=JSON */ """
                            {
                              "$schema": "https://json-schema.org/draft/2020-12/schema",
                              "type": "object",
                              "properties": {
                                "jacksonRequiredString": {
                                  "type": "string"
                                },
                                "jvRequiredString": {
                                  "type": "string"
                                },
                                "swaggerRequiredString": {
                                  "type": "string"
                                },
                                "jvEmailString": {
                                  "type": "string",
                                  "format": "email"
                                }
                              },
                              "required": [
                                "jacksonRequiredString",
                                "jvRequiredString",
                                "swaggerRequiredString"
                              ]
                            }
                            """);
        }

        @Test
        void shouldThrowWhenClassIsNull() {
            assertThatExceptionOfType(NullPointerException.class)
                    .isThrownBy(() -> configMapper.getJsonSchema(null))
                    .withMessage("configClass must not be null");
        }

    }

    static class TestConfig implements RuntimeConfig {

        @JsonProperty(required = true)
        private String jacksonRequiredString;

        @NotNull
        private String jvRequiredString;

        @Schema(requiredMode = Schema.RequiredMode.REQUIRED)
        private String swaggerRequiredString;

        @Email
        private String jvEmailString;

        public String getJacksonRequiredString() {
            return jacksonRequiredString;
        }

        public void setJacksonRequiredString(final String jacksonRequiredString) {
            this.jacksonRequiredString = jacksonRequiredString;
        }

        public String getJvRequiredString() {
            return jvRequiredString;
        }

        public void setJvRequiredString(final String jvRequiredString) {
            this.jvRequiredString = jvRequiredString;
        }

        public String getSwaggerRequiredString() {
            return swaggerRequiredString;
        }

        public void setSwaggerRequiredString(final String swaggerRequiredString) {
            this.swaggerRequiredString = swaggerRequiredString;
        }

        public String getJvEmailString() {
            return jvEmailString;
        }

        public void setJvEmailString(final String jvEmailString) {
            this.jvEmailString = jvEmailString;
        }

    }

}