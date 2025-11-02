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

import io.pebbletemplates.pebble.error.AttributeNotFoundException;
import io.pebbletemplates.pebble.error.PebbleException;
import org.junit.Test;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

public class ConfigTemplateRendererTest {

    private final ConfigTemplateRenderer renderer = new ConfigTemplateRenderer(secret -> "SECRET_VALUE_" + secret);

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
    public void shouldRenderStringFieldsOfObject() {
        final var config = new SimpleConfig();
        config.url = "https://{{ secret('API_KEY') }}@example.com";
        config.timeout = 30;
        config.enabled = true;

        final SimpleConfig result = renderer.renderObject(config);

        assertThat(result).isNotNull();
        assertThat(result).isSameAs(config);
        assertThat(result.url).isEqualTo("https://SECRET_VALUE_API_KEY@example.com");
        assertThat(result.timeout).isEqualTo(30);
        assertThat(result.enabled).isTrue();
    }

    @Test
    public void shouldRenderStringFieldsOfNestedObjects() {
        final var parent = new ParentConfig();
        parent.name = "Parent {{ secret('NAME') }}";

        final var child = new ChildConfig();
        child.value = "Child {{ secret('VALUE') }}";
        child.count = 5;
        parent.child = child;

        renderer.renderObject(parent);

        assertThat(parent.name).isEqualTo("Parent SECRET_VALUE_NAME");
        assertThat(parent.child.value).isEqualTo("Child SECRET_VALUE_VALUE");
        assertThat(parent.child.count).isEqualTo(5);
    }

    @Test
    public void shouldRenderStringFieldsOfCollectionItems() {
        final var config = new ConfigWithList();
        config.items = new ArrayList<>();

        final var item1 = new SimpleConfig();
        item1.url = "{{ secret('URL1') }}";
        config.items.add(item1);

        final var item2 = new SimpleConfig();
        item2.url = "{{ secret('URL2') }}";
        config.items.add(item2);

        renderer.renderObject(config);

        assertThat(config.items.get(0).url).isEqualTo("SECRET_VALUE_URL1");
        assertThat(config.items.get(1).url).isEqualTo("SECRET_VALUE_URL2");
    }

    @Test
    public void shouldRenderStringFieldsOfMapValues() {
        final var config = new ConfigWithMap();
        config.settings = new HashMap<>();

        final var setting1 = new SimpleConfig();
        setting1.url = "{{ secret('S1') }}";
        config.settings.put("first", setting1);

        final var setting2 = new SimpleConfig();
        setting2.url = "{{ secret('S2') }}";
        config.settings.put("second", setting2);

        renderer.renderObject(config);

        assertThat(config.settings.get("first").url).isEqualTo("SECRET_VALUE_S1");
        assertThat(config.settings.get("second").url).isEqualTo("SECRET_VALUE_S2");
    }

    @Test
    public void shouldNotThrowForNullStringFields() {
        final var config = new SimpleConfig();
        config.url = null;
        config.description = "Test {{ secret('DESC') }}";

        renderer.renderObject(config);

        assertThat(config.url).isNull();
        assertThat(config.description).isEqualTo("Test SECRET_VALUE_DESC");
    }

    @Test
    public void shouldHandleCircularReferences() {
        final var node1 = new CircularNode();
        node1.name = "Node1 {{ secret('N1') }}";

        final var node2 = new CircularNode();
        node2.name = "Node2 {{ secret('N2') }}";

        node1.next = node2;
        node2.next = node1;

        renderer.renderObject(node1);

        assertThat(node1.name).isEqualTo("Node1 SECRET_VALUE_N1");
        assertThat(node2.name).isEqualTo("Node2 SECRET_VALUE_N2");
    }

    @Test
    public void shouldNotThrowForFieldsWithJavaLangType() {
        final var config = new ConfigWithJavaTypes();
        config.value = "{{ secret('VAL') }}";
        config.wrapper = 42;
        config.stringLiteral = "literal";

        renderer.renderObject(config);

        assertThat(config.value).isEqualTo("SECRET_VALUE_VAL");
        assertThat(config.wrapper).isEqualTo(42);
        assertThat(config.stringLiteral).isEqualTo("literal");
    }

    @Test
    public void shouldNotRenderFinalStringFields() {
        final var config = new ConfigWithFinalField();
        config.mutableField = "{{ secret('M') }}";

        renderer.renderObject(config);

        assertThat(config.finalField).isEqualTo("FINAL_VALUE");
        assertThat(config.mutableField).isEqualTo("SECRET_VALUE_M");
    }

    @Test
    public void shouldRenderStringFieldsOfSuperClasses() {
        final var config = new DerivedConfig();
        config.baseField = "Base {{ secret('BASE') }}";
        config.derivedField = "Derived {{ secret('DERIVED') }}";

        renderer.renderObject(config);

        assertThat(config.baseField).isEqualTo("Base SECRET_VALUE_BASE");
        assertThat(config.derivedField).isEqualTo("Derived SECRET_VALUE_DERIVED");
    }

    @Test
    public void shouldNotRenderNull() {
        final SimpleConfig result = renderer.renderObject(null);
        assertThat(result).isNull();
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

    static class SimpleConfig {
        String url;
        String description;
        int timeout;
        boolean enabled;
    }

    static class ParentConfig {
        String name;
        ChildConfig child;
    }

    static class ChildConfig {
        String value;
        int count;
    }

    static class ConfigWithList {
        List<SimpleConfig> items;
    }

    static class ConfigWithMap {
        Map<String, SimpleConfig> settings;
    }

    static class CircularNode {
        String name;
        CircularNode next;
    }

    static class ConfigWithJavaTypes {
        String value;
        Integer wrapper;
        String stringLiteral;
    }

    static class ConfigWithFinalField {
        final String finalField = "FINAL_VALUE";
        String mutableField;
    }

    static class BaseConfig {
        String baseField;
    }

    static class DerivedConfig extends BaseConfig {
        String derivedField;
    }

}