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
package org.dependencytrack.notification.publishing.jira;

import org.dependencytrack.plugin.api.config.ConfigTypes;
import org.dependencytrack.plugin.api.config.RuntimeConfigDefinition;

/**
 * @since 5.7.0
 */
final class JiraNotificationPublisherRuleConfigs {

    static final RuntimeConfigDefinition<String> USERNAME_CONFIG =
            new RuntimeConfigDefinition<>(
                    "username",
                    "",
                    ConfigTypes.STRING,
                    null,
                    false,
                    false);
    static final RuntimeConfigDefinition<String> PASSWORD_OR_TOKEN_CONFIG =
            new RuntimeConfigDefinition<>(
                    "password.or.token",
                    "",
                    ConfigTypes.STRING,
                    null,
                    true,
                    true);
    static final RuntimeConfigDefinition<String> PROJECT_KEY_CONFIG =
            new RuntimeConfigDefinition<>(
                    "project.key",
                    "",
                    ConfigTypes.STRING,
                    null,
                    true,
                    false);
    static final RuntimeConfigDefinition<String> TICKET_TYPE_CONFIG =
            new RuntimeConfigDefinition<>(
                    "ticket.type",
                    "",
                    ConfigTypes.STRING,
                    null,
                    true,
                    false);

    private JiraNotificationPublisherRuleConfigs() {
    }

}
