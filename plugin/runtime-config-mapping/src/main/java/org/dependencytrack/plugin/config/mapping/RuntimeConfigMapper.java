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

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.github.victools.jsonschema.generator.OptionPreset;
import com.github.victools.jsonschema.generator.SchemaGenerator;
import com.github.victools.jsonschema.generator.SchemaGeneratorConfigBuilder;
import com.github.victools.jsonschema.generator.SchemaVersion;
import com.github.victools.jsonschema.module.jackson.JacksonModule;
import com.github.victools.jsonschema.module.jackson.JacksonOption;
import com.github.victools.jsonschema.module.jakarta.validation.JakartaValidationModule;
import com.github.victools.jsonschema.module.jakarta.validation.JakartaValidationOption;
import com.github.victools.jsonschema.module.swagger2.Swagger2Module;
import com.networknt.schema.JsonSchema;
import com.networknt.schema.JsonSchemaFactory;
import com.networknt.schema.SpecVersion;
import com.networknt.schema.ValidationMessage;
import com.networknt.schema.serialization.DefaultJsonNodeReader;
import org.dependencytrack.plugin.api.config.RuntimeConfig;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import static java.util.Objects.requireNonNull;

/**
 * Mapper of {@link RuntimeConfig}s.
 * <p>
 * The mapper fulfills the following purposes:
 * <ul>
 *     <li>Generates JSON schemas from {@link RuntimeConfig} classes</li>
 *     <li>Serializes and deserializes {@link RuntimeConfig} instances to and from YAML</li>
 *     <li>Validates {@link RuntimeConfig} instances against their respective JSON schema</li>
 * </ul>
 * <p>
 * Schemas are generated lazily, on-demand. Generated schemas are cached.
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
    private final ObjectMapper yamlMapper;
    private final SchemaGenerator schemaGenerator;
    private final JsonSchemaFactory schemaFactory;
    private final Map<Class<? extends RuntimeConfig>, JsonSchema> schemaCache;

    RuntimeConfigMapper() {
        this.jsonMapper = new ObjectMapper()
                .setDefaultPropertyInclusion(JsonInclude.Include.NON_EMPTY);
        this.yamlMapper = new ObjectMapper(new YAMLFactory())
                .setDefaultPropertyInclusion(JsonInclude.Include.NON_EMPTY);
        this.schemaGenerator = new SchemaGenerator(
                new SchemaGeneratorConfigBuilder(
                        this.jsonMapper,
                        SchemaVersion.DRAFT_2020_12,
                        OptionPreset.PLAIN_JSON)
                        .with(new JacksonModule(
                                JacksonOption.RESPECT_JSONPROPERTY_ORDER,
                                JacksonOption.RESPECT_JSONPROPERTY_REQUIRED))
                        .with(new JakartaValidationModule(
                                JakartaValidationOption.NOT_NULLABLE_FIELD_IS_REQUIRED))
                        .with(new Swagger2Module())
                        .build());
        this.schemaFactory = JsonSchemaFactory
                .builder(JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V202012))
                .jsonNodeReader(
                        DefaultJsonNodeReader.builder()
                                .jsonMapper(this.jsonMapper)
                                .yamlMapper(this.yamlMapper)
                                .build())
                .build();
        this.schemaCache = new ConcurrentHashMap<>();
    }

    public static RuntimeConfigMapper getInstance() {
        return INSTANCE;
    }

    /**
     * Deserialize a given runtime config in YAML format.
     *
     * @param configYaml  The config in YAML format.
     * @param configClass Class to deserialize the config into.
     * @param <T>         Type of the config.
     * @return The deserialized {@link RuntimeConfig}.
     * @throws NullPointerException When either {@code configYaml} or {@code configClass} are {@code null}.
     * @throws UncheckedIOException When deserialization failed.
     */
    public <T extends RuntimeConfig> T deserialize(final String configYaml, final Class<T> configClass) {
        requireNonNull(configYaml, "configYaml must not be null");
        requireNonNull(configClass, "configClass must not be null");

        try {
            return yamlMapper.readValue(configYaml, configClass);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /**
     * Serialize a given runtime config to YAML.
     *
     * @param config The config to serialize.
     * @return The serialized config in YAML format.
     * @throws UncheckedIOException When serialization failed.
     * @throws NullPointerException When {@code config} is {@code null}.
     */
    public String serialize(final RuntimeConfig config) {
        requireNonNull(config, "config must not be null");

        try {
            return yamlMapper.writerWithDefaultPrettyPrinter().writeValueAsString(config);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /**
     * Get the JSON schema for a given config class.
     *
     * @param configClass The config class to get the JSON schema for.
     * @return The JSON schema.
     * @throws NullPointerException When {@code configClass} is {@code null}.
     * @throws UncheckedIOException When generating the JSON schema failed.
     */
    public String getJsonSchema(final Class<? extends RuntimeConfig> configClass) {
        requireNonNull(configClass, "configClass must not be null");

        final JsonSchema schema = getSchemaForClass(configClass);

        try {
            return jsonMapper.writeValueAsString(schema.getSchemaNode());
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /**
     * Validate a given config against its JSON schema.
     *
     * @param config The config to validate.
     * @throws NullPointerException             When {@code config} is {@code null}.
     * @throws RuntimeConfigValidationException When the config failed validation.
     */
    public void validate(final RuntimeConfig config) {
        requireNonNull(config, "config must not be null");

        final JsonSchema schema = getSchemaForClass(config.getClass());
        final JsonNode configNode = jsonMapper.convertValue(config, JsonNode.class);

        final Set<ValidationMessage> validationMessages = schema.validate(configNode);
        if (!validationMessages.isEmpty()) {
            throw new RuntimeConfigValidationException(validationMessages);
        }
    }

    /**
     * Validate a given config in YAML format against its JSON schema.
     *
     * @param configYaml  The config to validate in YAML format.
     * @param configClass The config class.
     * @throws NullPointerException             When either {@code configYaml} or {@code configClass} are {@code null}.
     * @throws UncheckedIOException             When parsing the config YAML failed.
     * @throws RuntimeConfigValidationException When the config failed validation.
     */
    public void validateYaml(final String configYaml, final Class<? extends RuntimeConfig> configClass) {
        requireNonNull(configClass, "configClass must not be null");
        requireNonNull(configYaml, "configYaml must not be null");

        final JsonSchema schema = getSchemaForClass(configClass);

        final JsonNode configNode;
        try {
            configNode = yamlMapper.readValue(configYaml, JsonNode.class);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }

        final Set<ValidationMessage> validationMessages = schema.validate(configNode);
        if (!validationMessages.isEmpty()) {
            throw new RuntimeConfigValidationException(validationMessages);
        }
    }

    private JsonSchema getSchemaForClass(final Class<? extends RuntimeConfig> configClass) {
        return schemaCache.computeIfAbsent(configClass, clazz -> {
            final JsonNode schemaNode = schemaGenerator.generateSchema(clazz);
            return schemaFactory.getSchema(schemaNode);
        });
    }

}
