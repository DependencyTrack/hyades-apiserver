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
 * Marker interface for an extension configuration that is modifiable at runtime.
 * <p>
 * The platform generates JSON schemas from metadata in {@link RuntimeConfig} implementations.
 * JSON schema is used for documentation and validation purposes. Extension authors can add
 * metadata using annotations from any of the following libraries:
 * <ul>
 *     <li>Jackson</li>
 *     <li>Jakarta Validation</li>
 *     <li>Swagger</li>
 * </ul>
 * Note that not all annotations have an effect, please refer to the corresponding documentation of
 * the jsonschema-generator project for details.
 * <p>
 * To ensure that schema generation, as well as serialization and deserialization works as expected,
 * {@link RuntimeConfig} implementations should be POJOs with <em>public</em> getters and setters for
 * all fields.
 * <p>
 * Extension authors are strongly encouraged to verify proper JSON schema generation using
 * {@code AbstractRuntimeConfigTest} from the {@code org.dependencytrack:plugin-testing} library.
 *
 * @see <a href="https://beanvalidation.org/">Jakarta Validation</a>
 * @see <a href="https://github.com/FasterXML/jackson-annotations">jackson-annotations</a>
 * @see <a href="https://github.com/victools/jsonschema-generator">jsonschema-generator</a>
 * @see <a href="https://github.com/swagger-api/swagger-core/wiki/Swagger-2.X---Annotations>Swagger 2.X Annotations</a>
 * @see <a href="https://github.com/victools/jsonschema-generator/tree/main/jsonschema-module-jackson#features">Supported Jackson annotations</a>
 * @see <a href="https://github.com/victools/jsonschema-generator/tree/main/jsonschema-module-jakarta-validation#features">Supported Jakarta Validation annotations</a>
 * @see <a href="https://github.com/victools/jsonschema-generator/tree/main/jsonschema-module-swagger-2#features">Supported Swagger annotations</a>
 * @since 5.7.0
 */
public interface RuntimeConfig {
}
