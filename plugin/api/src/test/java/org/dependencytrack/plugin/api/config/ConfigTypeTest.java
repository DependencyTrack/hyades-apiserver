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
package org.dependencytrack.plugin.api.config;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.net.URI;
import java.net.URL;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class ConfigTypeTest {

    @Nested
    class BooleanTest {

        private static Stream<Arguments> fromStringShouldReturnCorrectValueArguments() {
            return Stream.of(
                    Arguments.of(null, null),
                    Arguments.of("false", false),
                    Arguments.of("true", true));
        }

        @ParameterizedTest
        @MethodSource("fromStringShouldReturnCorrectValueArguments")
        void fromStringShouldReturnCorrectValue(final String inputValue, final Boolean expectedValue) {
            final var configType = new ConfigType.Boolean();
            assertThat(configType.fromString(inputValue)).isEqualTo(expectedValue);
        }

        @Test
        void fromStringShouldReturnFalseForInvalidInputValue() {
            final var configType = new ConfigType.Boolean();
            assertThat(configType.fromString("invalid")).isEqualTo(false);
        }

        private static Stream<Arguments> toStringShouldReturnCorrectValueArguments() {
            return Stream.of(
                    Arguments.of(null, null),
                    Arguments.of(false, "false"),
                    Arguments.of(true, "true"));
        }

        @ParameterizedTest
        @MethodSource("toStringShouldReturnCorrectValueArguments")
        void toStringShouldReturnCorrectValue(final Boolean inputValue, final String expectedValue) {
            final var configType = new ConfigType.Boolean();
            assertThat(configType.toString(inputValue)).isEqualTo(expectedValue);
        }

    }

    @Nested
    class DurationTest {

        private static Stream<Arguments> fromStringShouldReturnCorrectValueArguments() {
            return Stream.of(
                    Arguments.of(null, null),
                    Arguments.of("PT0.5S", Duration.ofMillis(500)),
                    Arguments.of("PT5M", Duration.ofMinutes(5)));
        }

        @ParameterizedTest
        @MethodSource("fromStringShouldReturnCorrectValueArguments")
        void fromStringShouldReturnCorrectValue(final String inputValue, final Duration expectedValue) {
            final var configType = new ConfigType.Duration();
            assertThat(configType.fromString(inputValue)).isEqualTo(expectedValue);
        }

        @Test
        void fromStringShouldThrowForInvalidInputValue() {
            final var configType = new ConfigType.Duration();
            assertThatExceptionOfType(DateTimeParseException.class)
                    .isThrownBy(() -> configType.fromString("invalid"));
        }

        private static Stream<Arguments> toStringShouldReturnCorrectValueArguments() {
            return Stream.of(
                    Arguments.of(null, null),
                    Arguments.of(Duration.ofMillis(500), "PT0.5S"),
                    Arguments.of(Duration.ofMinutes(5), "PT5M"));
        }

        @ParameterizedTest
        @MethodSource("toStringShouldReturnCorrectValueArguments")
        void toStringShouldReturnCorrectValue(final Duration inputValue, final String expectedValue) {
            final var configType = new ConfigType.Duration();
            assertThat(configType.toString(inputValue)).isEqualTo(expectedValue);
        }

    }

    @Nested
    class InstantTest {

        private static Stream<Arguments> fromStringShouldReturnCorrectValueArguments() {
            return Stream.of(
                    Arguments.of(null, null),
                    Arguments.of("666666000", Instant.ofEpochSecond(666666)));
        }

        @ParameterizedTest
        @MethodSource("fromStringShouldReturnCorrectValueArguments")
        void fromStringShouldReturnCorrectValue(final String inputValue, final Instant expectedValue) {
            final var configType = new ConfigType.Instant();
            assertThat(configType.fromString(inputValue)).isEqualTo(expectedValue);
        }

        @Test
        void fromStringShouldThrowForInvalidInputValue() {
            final var configType = new ConfigType.Instant();
            assertThatExceptionOfType(NumberFormatException.class)
                    .isThrownBy(() -> configType.fromString("invalid"));
        }

        private static Stream<Arguments> toStringShouldReturnCorrectValueArguments() {
            return Stream.of(
                    Arguments.of(null, null),
                    Arguments.of(Instant.ofEpochSecond(666666), "666666000"));
        }

        @ParameterizedTest
        @MethodSource("toStringShouldReturnCorrectValueArguments")
        void toStringShouldReturnCorrectValue(final Instant inputValue, final String expectedValue) {
            final var configType = new ConfigType.Instant();
            assertThat(configType.toString(inputValue)).isEqualTo(expectedValue);
        }

    }

    @Nested
    class IntegerTest {

        private static Stream<Arguments> fromStringShouldReturnCorrectValueArguments() {
            return Stream.of(
                    Arguments.of(null, null),
                    Arguments.of("123", 123),
                    Arguments.of("-123", -123));
        }

        @ParameterizedTest
        @MethodSource("fromStringShouldReturnCorrectValueArguments")
        void fromStringShouldReturnCorrectValue(final String inputValue, final Integer expectedValue) {
            final var configType = new ConfigType.Integer();
            assertThat(configType.fromString(inputValue)).isEqualTo(expectedValue);
        }

        @Test
        void fromStringShouldThrowForInvalidInputValue() {
            final var configType = new ConfigType.Integer();
            assertThatExceptionOfType(NumberFormatException.class)
                    .isThrownBy(() -> configType.fromString("invalid"));
        }

        private static Stream<Arguments> toStringShouldReturnCorrectValueArguments() {
            return Stream.of(
                    Arguments.of(null, null),
                    Arguments.of(123, "123"),
                    Arguments.of(-123, "-123"));
        }

        @ParameterizedTest
        @MethodSource("toStringShouldReturnCorrectValueArguments")
        void toStringShouldReturnCorrectValue(final Integer inputValue, final String expectedValue) {
            final var configType = new ConfigType.Integer();
            assertThat(configType.toString(inputValue)).isEqualTo(expectedValue);
        }

    }

    @Nested
    class PathTest {

        private static Stream<Arguments> fromStringShouldReturnCorrectValueArguments() {
            return Stream.of(
                    Arguments.of(null, null),
                    Arguments.of("foo", Path.of("foo")),
                    Arguments.of("/foo/bar", Path.of("/foo/bar")));
        }

        @ParameterizedTest
        @MethodSource("fromStringShouldReturnCorrectValueArguments")
        void fromStringShouldReturnCorrectValue(final String inputValue, final Path expectedValue) {
            final var configType = new ConfigType.Path();
            assertThat(configType.fromString(inputValue)).isEqualTo(expectedValue);
        }

        private static Stream<Arguments> toStringShouldReturnCorrectValueArguments() {
            return Stream.of(
                    Arguments.of(null, null),
                    Arguments.of(Path.of("foo"), "foo"),
                    Arguments.of(Path.of("/foo/bar"), "/foo/bar"));
        }

        @ParameterizedTest
        @MethodSource("toStringShouldReturnCorrectValueArguments")
        void toStringShouldReturnCorrectValue(final Path inputValue, final String expectedValue) {
            final var configType = new ConfigType.Path();
            assertThat(configType.toString(inputValue)).isEqualTo(expectedValue);
        }

    }

    @Nested
    class StringTest {

        private static Stream<Arguments> fromStringShouldReturnCorrectValueArguments() {
            return Stream.of(
                    Arguments.of(null, null),
                    Arguments.of("foo", "foo"));
        }

        @ParameterizedTest
        @MethodSource("fromStringShouldReturnCorrectValueArguments")
        void fromStringShouldReturnCorrectValue(final String inputValue, final String expectedValue) {
            final var configType = new ConfigType.String();
            assertThat(configType.fromString(inputValue)).isEqualTo(expectedValue);
        }

        private static Stream<Arguments> toStringShouldReturnCorrectValueArguments() {
            return Stream.of(
                    Arguments.of(null, null),
                    Arguments.of("foo", "foo"));
        }

        @ParameterizedTest
        @MethodSource("toStringShouldReturnCorrectValueArguments")
        void toStringShouldReturnCorrectValue(final String inputValue, final String expectedValue) {
            final var configType = new ConfigType.String();
            assertThat(configType.toString(inputValue)).isEqualTo(expectedValue);
        }

    }

    @Nested
    class StringListTest {

        private static Stream<Arguments> fromStringShouldReturnCorrectValueArguments() {
            return Stream.of(
                    Arguments.of(null, null),
                    Arguments.of("foo, bar", List.of("foo", "bar")));
        }

        @ParameterizedTest
        @MethodSource("fromStringShouldReturnCorrectValueArguments")
        void fromStringShouldReturnCorrectValue(final String inputValue, final List<String> expectedValue) {
            final var configType = new ConfigType.StringList(null);
            assertThat(configType.fromString(inputValue)).isEqualTo(expectedValue);
        }

        @ParameterizedTest
        @MethodSource("fromStringShouldReturnCorrectValueArguments")
        void fromStringShouldReturnCorrectValueWithAllowedValues() {
            final var configType = new ConfigType.StringList(Set.of("foo", "bar"));
            assertThatExceptionOfType(IllegalArgumentException.class)
                    .isThrownBy(() -> configType.fromString("foo, invalid"))
                    .withMessageContaining("Invalid value");
        }

        private static Stream<Arguments> toStringShouldReturnCorrectValueArguments() {
            return Stream.of(
                    Arguments.of(null, null),
                    Arguments.of(List.of("foo", "bar"), "foo,bar"));
        }

        @ParameterizedTest
        @MethodSource("toStringShouldReturnCorrectValueArguments")
        void toStringShouldReturnCorrectValue(final List<String> inputValue, final String expectedValue) {
            final var configType = new ConfigType.StringList(null);
            assertThat(configType.toString(inputValue)).isEqualTo(expectedValue);
        }

        @ParameterizedTest
        @MethodSource("toStringShouldReturnCorrectValueArguments")
        void toStringShouldReturnCorrectValueWithAllowedValues() {
            final var configType = new ConfigType.StringList(Set.of("foo", "bar"));
            assertThatExceptionOfType(IllegalArgumentException.class)
                    .isThrownBy(() -> configType.toString(List.of("foo", "invalid")))
                    .withMessageContaining("Invalid value");
        }

    }

    @Nested
    class URLTest {

        private static Stream<Arguments> fromStringShouldReturnCorrectValueArguments() throws Exception {
            return Stream.of(
                    Arguments.of(null, null),
                    Arguments.of("https://example.com/foo", URI.create("https://example.com/foo").toURL()));
        }

        @ParameterizedTest
        @MethodSource("fromStringShouldReturnCorrectValueArguments")
        void fromStringShouldReturnCorrectValue(final String inputValue, final URL expectedValue) {
            final var configType = new ConfigType.URL();
            assertThat(configType.fromString(inputValue)).isEqualTo(expectedValue);
        }

        @Test
        void fromStringShouldThrowForInvalidInputValue() {
            final var configType = new ConfigType.URL();
            assertThatExceptionOfType(IllegalArgumentException.class)
                    .isThrownBy(() -> configType.fromString("invalid"));
        }

        private static Stream<Arguments> toStringShouldReturnCorrectValueArguments() throws Exception {
            return Stream.of(
                    Arguments.of(null, null),
                    Arguments.of(URI.create("https://example.com/foo").toURL(), "https://example.com/foo"));
        }

        @ParameterizedTest
        @MethodSource("toStringShouldReturnCorrectValueArguments")
        void toStringShouldReturnCorrectValue(final URL inputValue, final String expectedValue) {
            final var configType = new ConfigType.URL();
            assertThat(configType.toString(inputValue)).isEqualTo(expectedValue);
        }

    }

}