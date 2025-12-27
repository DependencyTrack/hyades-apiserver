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
package org.dependencytrack.config.templating;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.pebbletemplates.pebble.error.AttributeNotFoundException;
import io.pebbletemplates.pebble.error.PebbleException;
import org.junit.Test;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatNoException;

public class ConfigTemplateRendererTest {

    private final ConfigTemplateRenderer renderer = new ConfigTemplateRenderer(secret -> "SECRET_VALUE_" + secret);
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    public void shouldRenderStringLiteral() {
        assertThat(renderer.render("foo")).isEqualTo("foo");
        assertThat(renderer.render("{{ foo")).isEqualTo("{{ foo");
        assertThat(renderer.render("foo }}")).isEqualTo("foo }}");
        assertThat(renderer.render("{ foo }")).isEqualTo("{ foo }");
    }

    @Test
    public void shouldSupportBase64DecodeFilter() {
        assertThat(renderer.render("{{ 'dGVzdA==' | base64decode }}")).isEqualTo("test");
    }

    @Test
    public void shouldSupportBase64EncodeFilter() {
        assertThat(renderer.render("{{ 'test' | base64encode }}")).isEqualTo("dGVzdA==");
    }

    @Test
    public void shouldSupportDefaultFilter() {
        final ConfigTemplateRenderer renderer = new ConfigTemplateRenderer(secret -> null);
        assertThat(renderer.render("{{ secret('doesNotExist') | default('defaultSecret') }}")).isEqualTo("defaultSecret");
    }

    @Test
    public void shouldSupportLowerFilter() {
        assertThat(renderer.render("{{ 'TeSt' | lower }}")).isEqualTo("test");
    }

    @Test
    public void shouldSupportTrimFilter() {
        assertThat(renderer.render("{{ ' test   ' | trim }}")).isEqualTo("test");
    }

    @Test
    public void shouldSupportUpperFilter() {
        assertThat(renderer.render("{{ 'TeSt' | upper }}")).isEqualTo("TEST");
    }

    @Test
    public void shouldSupportUrlEncodeFilter() {
        assertThat(renderer.render("{{ 't es@!&' | urlencode }}")).isEqualTo("t+es%40%21%26");
    }

    @Test
    public void shouldSupportSecretFunction() {
        final String result = renderer.render("{{ secret('mySecret') }}");
        assertThat(result).isEqualTo("SECRET_VALUE_mySecret");
    }

    @Test
    public void shouldThrowForMissingSecretFunctionArgument() {
        assertThatExceptionOfType(PebbleException.class)
                .isThrownBy(() -> renderer.render("{{ secret() }}"))
                .withMessage("Missing argument: name ({{ secret() }}:1)");
    }

    @Test
    public void shouldThrowForInvalidSecretFunctionArgumentType() {
        assertThatExceptionOfType(PebbleException.class)
                .isThrownBy(() -> renderer.render("{{ secret(123) }}"))
                .withMessage("Argument name must be of type String, but was: Long ({{ secret(123) }}:1)");
    }

    @Test
    public void renderJsonShouldRenderStringFieldsOfObject() throws Exception {
        final JsonNode jsonNode = objectMapper.readTree(/* language=JSON */ """
                {
                  "url": "https://{{ secret('API_KEY') }}@example.com",
                  "timeout": 30,
                  "enabled": true
                }
                """);

        renderer.renderJson(jsonNode);

        assertThatJson(jsonNode).isEqualTo(/* language=JSON */ """
                {
                  "url": "https://SECRET_VALUE_API_KEY@example.com",
                  "timeout": 30,
                  "enabled": true
                }
                """);
    }

    @Test
    public void renderJsonShouldRenderStringFieldsOfNestedObjects() throws Exception {
        final JsonNode jsonNode = objectMapper.readTree(/* language=JSON */ """
                {
                  "name": "Parent {{ secret('NAME') }}",
                  "child": {
                    "value": "Child {{ secret('VALUE') }}",
                    "count": 5
                  }
                }
                """);

        renderer.renderJson(jsonNode);

        assertThatJson(jsonNode).isEqualTo(/* language=JSON */ """
                {
                  "name": "Parent SECRET_VALUE_NAME",
                  "child": {
                    "value": "Child SECRET_VALUE_VALUE",
                    "count": 5
                  }
                }
                """);
    }

    @Test
    public void renderJsonShouldRenderStringFieldsOfCollectionItems() throws Exception {
        final JsonNode jsonNode = objectMapper.readTree(/* language=JSON */ """
                [
                  {
                    "url": "{{ secret('URL1') }}"
                  },
                  {
                    "url": "{{ secret('URL2') }}"
                  }
                ]
                """);

        renderer.renderJson(jsonNode);

        assertThatJson(jsonNode).isEqualTo(/* language=JSON */ """
                [
                  {
                    "url": "SECRET_VALUE_URL1"
                  },
                  {
                    "url": "SECRET_VALUE_URL2"
                  }
                ]
                """);
    }

    @Test
    public void renderJsonShouldNotThrowForNullStringFields() throws Exception {
        final JsonNode jsonNode = objectMapper.readTree(/* language=JSON */ """
                {
                  "url": null
                }
                """);

        assertThatNoException().isThrownBy(() -> renderer.renderJson(jsonNode));

        assertThatJson(jsonNode).isEqualTo(/* language=JSON */ """
                {
                  "url": null
                }
                """);
    }

    @Test
    public void shouldThrowWhenVariableDoesNotExist() {
        assertThatExceptionOfType(AttributeNotFoundException.class)
                .isThrownBy(() -> renderer.render("{{ foo }}"));
    }

    @Test
    public void shouldThrowOnMethodAccess() {
        assertThatExceptionOfType(AttributeNotFoundException.class)
                .isThrownBy(() -> renderer.render("{{ 'foo'.getClass() }}"));

        assertThatExceptionOfType(AttributeNotFoundException.class)
                .isThrownBy(() -> renderer.render("{{ 'foo'.hashCode() }}"));

        assertThatExceptionOfType(AttributeNotFoundException.class)
                .isThrownBy(() -> renderer.render("{{ 1.toString() }}"));
    }

}