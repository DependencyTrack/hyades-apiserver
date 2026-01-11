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
package org.dependencytrack.provisioning.config;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.JsonNodeType;
import com.fasterxml.jackson.databind.node.TextNode;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.networknt.schema.JsonSchema;
import com.networknt.schema.JsonSchemaFactory;
import com.networknt.schema.SpecVersion;
import com.networknt.schema.ValidationMessage;
import com.networknt.schema.serialization.DefaultJsonNodeReader;
import org.dependencytrack.provisioning.config.ProvisioningResource.ExtensionConfigResource;
import org.dependencytrack.provisioning.config.ProvisioningResource.SecretResource;
import org.dependencytrack.provisioning.config.ProvisioningResource.TeamResource;
import org.dependencytrack.provisioning.config.ProvisioningResource.UserResource;
import org.dependencytrack.provisioning.config.schema.ProvisioningConfigV0;
import org.dependencytrack.provisioning.config.schema.Resource;
import org.eclipse.microprofile.config.Config;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.stream.Collectors;

import static java.util.Objects.requireNonNull;

/**
 * @since 5.7.0
 */
public final class ProvisioningConfigLoader {

    private static final Set<String> SUPPORTED_VERSIONS = Set.of("v0");

    private final Config config;
    private final ObjectMapper yamlMapper;
    private final JsonSchemaFactory jsonSchemaFactory;

    public ProvisioningConfigLoader(Config config) {
        this.config = requireNonNull(config, "config must not be null");
        this.yamlMapper = new ObjectMapper(new YAMLFactory());
        this.jsonSchemaFactory = JsonSchemaFactory
                .builder(JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V202012))
                .jsonNodeReader(
                        DefaultJsonNodeReader.builder()
                                .jsonMapper(new ObjectMapper())
                                .yamlMapper(yamlMapper)
                                .build())
                .build();
    }

    public List<ProvisioningResource> load(Path path) {
        final JsonNode jsonNode;
        try (final InputStream fis = Files.newInputStream(path)) {
            jsonNode = yamlMapper.readTree(fis);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to read config file: " + path, e);
        }

        final JsonNode versionNode = jsonNode.get("version");
        if (versionNode == null) {
            throw new IllegalStateException("Config is missing the 'version' field");
        }

        final String version;
        if (versionNode instanceof final TextNode versionTextNode) {
            version = requireSupportedVersion(versionTextNode.asText());
        } else {
            throw new IllegalStateException(
                    "'version' field must be of type %s, but is: %s".formatted(
                            JsonNodeType.STRING, versionNode.getNodeType()));
        }

        final JsonSchema jsonSchema = getJsonSchema(version);

        final Set<ValidationMessage> validationMessages = jsonSchema.validate(jsonNode);
        if (!validationMessages.isEmpty()) {
            throw new IllegalStateException("Config file %s is invalid: %s".formatted(
                    path, validationMessages.stream().map(ValidationMessage::getMessage).collect(Collectors.joining(", "))));
        }

        // TODO: Resolve expressions, i.e. ${config:foo.bar} -> config.getValue("foo.bar")

        final var config = yamlMapper.convertValue(jsonNode, ProvisioningConfigV0.class);

        return config.getResources().stream()
                .map(resource -> switch (resource.getKind()) {
                    case EXTENSION_CONFIG -> getExtensionConfigResource(resource);
                    case SECRET -> getSecretResource(resource);
                    case TEAM -> getTeamResource(resource);
                    case USER -> getUserResource(resource);
                })
                .toList();
    }

    private JsonSchema getJsonSchema(String version) {
        try (final InputStream fis = getClass().getResourceAsStream(
                "schema/provisioning-config-%s.schema.json".formatted(version))) {
            if (fis == null) {
                throw new NoSuchElementException("No JSON schema found for version " + version);
            }

            return jsonSchemaFactory.getSchema(fis);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to load JSON schema", e);
        }
    }

    private ProvisioningResource getExtensionConfigResource(Resource resource) {
        return yamlMapper.convertValue(resource.getSpec(), ExtensionConfigResource.class);
    }

    private ProvisioningResource getSecretResource(Resource resource) {
        return yamlMapper.convertValue(resource.getSpec(), SecretResource.class);
    }

    private ProvisioningResource getTeamResource(Resource resource) {
        return yamlMapper.convertValue(resource.getSpec(), TeamResource.class);
    }

    private ProvisioningResource getUserResource(Resource resource) {
        return yamlMapper.convertValue(resource.getSpec(), UserResource.class);
    }

    private String requireSupportedVersion(String version) {
        if (SUPPORTED_VERSIONS.contains(version)) {
            return version;
        }

        throw new IllegalStateException(
                "Config version '%s' is not supported. Supported versions are: %s".formatted(
                        version, String.join(", ", SUPPORTED_VERSIONS)));
    }

}
