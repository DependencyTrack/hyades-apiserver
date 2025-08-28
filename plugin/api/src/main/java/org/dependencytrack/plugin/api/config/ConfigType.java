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

/**
 * @since 5.7.0
 */
public sealed interface ConfigType<T> {

    /**
     * @return The Java class backing this type.
     */
    Class<T> clazz();

    /**
     * Convert a given {@link java.lang.String} to the corresponding {@code T} value.
     *
     * @param value The value to convert.
     * @return The converted {@code T}, or {@code null} if {@code value} was {@code null}.
     */
    T fromString(java.lang.String value);

    /**
     * Convert a given {@code T} to the corresponding {@link java.lang.String} value.
     *
     * @param value The value to convert.
     * @return The converted {@link java.lang.String}, or {@code null} if {@code value} was {@code null}.
     */
    java.lang.String toString(T value);

    record Boolean() implements ConfigType<java.lang.Boolean> {

        @Override
        public Class<java.lang.Boolean> clazz() {
            return java.lang.Boolean.class;
        }

        @Override
        public java.lang.Boolean fromString(final java.lang.String value) {
            return value != null ? java.lang.Boolean.parseBoolean(value) : null;
        }

        @Override
        public java.lang.String toString(final java.lang.Boolean value) {
            return value != null ? java.lang.Boolean.toString(value) : null;
        }

    }

    record Duration() implements ConfigType<java.time.Duration> {

        @Override
        public Class<java.time.Duration> clazz() {
            return java.time.Duration.class;
        }

        @Override
        public java.time.Duration fromString(final java.lang.String value) {
            return value != null ? java.time.Duration.parse(value) : null;
        }

        @Override
        public java.lang.String toString(final java.time.Duration value) {
            return value != null ? value.toString() : null;
        }

    }

    record Instant() implements ConfigType<java.time.Instant> {

        @Override
        public Class<java.time.Instant> clazz() {
            return java.time.Instant.class;
        }

        @Override
        public java.time.Instant fromString(final java.lang.String value) {
            return value != null ? java.time.Instant.parse(value) : null;
        }

        @Override
        public java.lang.String toString(final java.time.Instant value) {
            return value != null ? value.toString() : null;
        }

    }

    record Integer() implements ConfigType<java.lang.Integer> {

        @Override
        public Class<java.lang.Integer> clazz() {
            return java.lang.Integer.class;
        }

        @Override
        public java.lang.Integer fromString(final java.lang.String value) {
            return value != null ? java.lang.Integer.parseInt(value) : null;
        }

        @Override
        public java.lang.String toString(final java.lang.Integer value) {
            return value != null ? java.lang.Integer.toString(value) : null;
        }

    }

    record Path() implements ConfigType<java.nio.file.Path> {

        @Override
        public Class<java.nio.file.Path> clazz() {
            return java.nio.file.Path.class;
        }

        @Override
        public java.nio.file.Path fromString(final java.lang.String value) {
            return value != null ? java.nio.file.Path.of(value) : null;
        }

        @Override
        public java.lang.String toString(final java.nio.file.Path value) {
            return value != null ? value.toString() : null;
        }

    }

    record String() implements ConfigType<java.lang.String> {

        @Override
        public Class<java.lang.String> clazz() {
            return java.lang.String.class;
        }

        @Override
        public java.lang.String fromString(final java.lang.String value) {
            return value;
        }

        @Override
        public java.lang.String toString(final java.lang.String value) {
            return value;
        }

    }

}
