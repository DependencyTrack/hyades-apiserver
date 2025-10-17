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
package org.dependencytrack.notification.publishing.kafka;

import org.dependencytrack.plugin.api.config.ConfigTypes;
import org.dependencytrack.plugin.api.config.RuntimeConfigDefinition;

/**
 * @since 5.7.0
 */
final class KafkaNotificationPublisherRuleConfigs {

    static final RuntimeConfigDefinition<String> BOOTSTRAP_SERVERS_CONFIG =
            new RuntimeConfigDefinition<>(
                    "bootstrap.servers",
                    "",
                    ConfigTypes.STRING,
                    /* defaultValue */ null,
                    /* isRequired */ true,
                    /* isSecret */ false);
    static final RuntimeConfigDefinition<String> CLIENT_ID_CONFIG =
            new RuntimeConfigDefinition<>(
                    "client.id",
                    "",
                    ConfigTypes.STRING,
                    /* defaultValue */ "dependencytrack-notification-publisher",
                    /* isRequired */ true,
                    /* isSecret */ false);

    private KafkaNotificationPublisherRuleConfigs() {
    }

}
