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
package org.dependencytrack.init;

import alpine.Config;

import javax.sql.DataSource;

/**
 * Context available to {@link InitTask}s.
 * <p>
 * TODO: Introduce a tiny abstraction over {@link Config} such that
 *  Alpine specifics don't bleed through to {@link InitTask}s.
 *
 * @param config     A {@link Config} instance to read application configuration.
 * @param dataSource A {@link DataSource} which may be used for database interactions.
 * @since 5.6.0
 */
public record InitTaskContext(Config config, DataSource dataSource) {
}
