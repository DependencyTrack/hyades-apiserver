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
package org.dependencytrack.resources.v1.vo;

import com.fasterxml.jackson.annotation.JsonInclude;
import io.swagger.annotations.ApiModelProperty;

import java.util.List;

/**
 * @since 5.6.0
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record LoadedPluginListResponseItem(
        @ApiModelProperty(value = "Name of the plugin", required = true) String name,
        @ApiModelProperty(value = "Names of all loaded providers for the plugin") List<String> providers,
        @ApiModelProperty(value = "Name of the default provider for the plugin") String defaultProvider
) {
}
