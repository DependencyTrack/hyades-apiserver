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

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.networknt.schema.JsonMetaSchema;
import com.networknt.schema.JsonSchema;
import com.networknt.schema.JsonSchemaFactory;
import com.networknt.schema.NonValidationKeyword;
import com.networknt.schema.SpecVersion;
import com.networknt.schema.ValidationMessage;
import com.networknt.schema.serialization.DefaultJsonNodeReader;
import org.dependencytrack.plugin.api.config.RuntimeConfig;
import org.dependencytrack.plugin.api.config.RuntimeConfigSpec;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import static java.util.Objects.requireNonNull;

/**
 * Mapper of {@link RuntimeConfig}s.
 * <p>
 * The mapper fulfills the following purposes:
 * <ul>
 *     <li>Serializes and deserializes {@link RuntimeConfig} instances to and from JSON</li>
 *     <li>Validates {@link RuntimeConfig} instances against their respective JSON schema</li>
 * </ul>
 * <p>
 * This class is thread-safe. To make effective use of the schema cache,
 * prefer using the global instance available via {@link #getInstance()},
 * instead of creating new instances ad-hoc.
 *
 * @since 5.7.0
 */
public final class RuntimeConfigMapper {

    private static final RuntimeConfigMapper INSTANCE = new RuntimeConfigMapper();

    private final ObjectMapper jsonMapper;
    private final JsonSchemaFactory schemaFactory;
    private final Map<RuntimeConfigSpec, JsonSchema> schemaCache;

    RuntimeConfigMapper() {
        this.jsonMapper = new ObjectMapper()
                .setDefaultPropertyInclusion(JsonInclude.Include.NON_EMPTY);
        final JsonMetaSchema jsonMetaSchema = JsonMetaSchema.builder(
                        JsonMetaSchema.getV202012().getIri(),
                        JsonMetaSchema.getV202012())
                // Don't emit warnings when encountering jsonschema2pojo extensions.
                // https://github.com/joelittlejohn/jsonschema2pojo/wiki/Reference#extensions
                .keywords(List.of(
                        new NonValidationKeyword("existingJavaType"),
                        new NonValidationKeyword("javaEnumNames"),
                        new NonValidationKeyword("javaEnums"),
                        new NonValidationKeyword("javaInterfaces"),
                        new NonValidationKeyword("javaJsonView"),
                        new NonValidationKeyword("javaName"),
                        new NonValidationKeyword("javaType")))
                .build();
        this.schemaFactory = JsonSchemaFactory
                .builder(JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V202012))
                .jsonNodeReader(
                        DefaultJsonNodeReader.builder()
                                .jsonMapper(this.jsonMapper)
                                .build())
                .defaultMetaSchemaIri(jsonMetaSchema.getIri())
                .metaSchema(jsonMetaSchema)
                .build();
        this.schemaCache = new ConcurrentHashMap<>();
    }

    public static RuntimeConfigMapper getInstance() {
        return INSTANCE;
    }

    /**
     * Deserialize a given runtime config in JSON format.
     *
     * @param configJson  The config in JSON format.
     * @param configClass Class to deserialize the config into.
     * @param <T>         Type of the config.
     * @return The deserialized {@link RuntimeConfig}.
     * @throws NullPointerException When either {@code configJson} or {@code configClass} are {@code null}.
     * @throws UncheckedIOException When deserialization failed.
     */
    public <T extends RuntimeConfig> T deserialize(String configJson, Class<T> configClass) {
        requireNonNull(configJson, "configJson must not be null");
        requireNonNull(configClass, "configClass must not be null");

        try {
            return jsonMapper.readValue(configJson, configClass);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public <T extends RuntimeConfig> T convert(JsonNode configJsonNode, Class<T> configClass) {
        requireNonNull(configJsonNode, "configJsonNode must not be null");
        requireNonNull(configClass, "configClass must not be null");

        return jsonMapper.convertValue(configJsonNode, configClass);
    }

    /**
     * Serialize a given runtime config to JSON.
     *
     * @param config The config to serialize.
     * @return The serialized config in JSON format.
     * @throws UncheckedIOException When serialization failed.
     * @throws NullPointerException When {@code config} is {@code null}.
     */
    public String serialize(RuntimeConfig config) {
        requireNonNull(config, "config must not be null");

        try {
            return jsonMapper
                    .writerWithDefaultPrettyPrinter()
                    .writeValueAsString(config);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /**
     * Validate a given config against its JSON schema.
     *
     * @param config     The config to validate.
     * @param configSpec The applicable runtime config spec.
     * @throws NullPointerException             When either {@code config} or {@code configSchemaJson} are {@code null}.
     * @throws UncheckedIOException             When parsing the config JSON failed.
     * @throws RuntimeConfigValidationException When the config failed validation.
     */
    public JsonNode validate(RuntimeConfig config, RuntimeConfigSpec configSpec) {
        requireNonNull(config, "config must not be null");
        requireNonNull(configSpec, "configSpec must not be null");

        final JsonSchema schema = getSchema(configSpec);
        final JsonNode configNode = jsonMapper.convertValue(config, JsonNode.class);

        final Set<ValidationMessage> validationMessages = schema.validate(configNode);
        if (!validationMessages.isEmpty()) {
            throw new RuntimeConfigValidationException(validationMessages);
        }

        return configNode;
    }

    /**
     * Validate a given config in JSON format against its schema.
     *
     * @param configJson The config to validate in JSON format.
     * @param configSpec The applicable runtime config spec.
     * @throws NullPointerException             When either {@code configJson} or {@code configSchemaJson} are {@code null}.
     * @throws UncheckedIOException             When parsing the config JSON failed.
     * @throws RuntimeConfigValidationException When the config failed validation.
     */
    public JsonNode validateJson(String configJson, RuntimeConfigSpec configSpec) {
        requireNonNull(configJson, "configJson must not be null");
        requireNonNull(configSpec, "configSpec must not be null");

        final JsonSchema schema = getSchema(configSpec);

        final JsonNode configNode;
        try {
            configNode = jsonMapper.readValue(configJson, JsonNode.class);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }

        final Set<ValidationMessage> validationMessages = schema.validate(configNode);
        if (!validationMessages.isEmpty()) {
            throw new RuntimeConfigValidationException(validationMessages);
        }

        return configNode;
    }

    public ObjectMapper getJsonMapper() {
        return jsonMapper;
    }

    private JsonSchema getSchema(RuntimeConfigSpec configSpec) {
        return schemaCache.computeIfAbsent(
                configSpec,
                clazz -> {
                    final JsonNode schemaNode;
                    try {
                        schemaNode = jsonMapper.readValue(configSpec.schema(), JsonNode.class);
                    } catch (IOException e) {
                        throw new UncheckedIOException(e);
                    }

                    return schemaFactory.getSchema(schemaNode);
                });
    }

}
