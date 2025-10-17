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
package org.dependencytrack.plugin.api.notification.publishing;

import org.dependencytrack.plugin.api.notification.templating.TemplateRenderer;

/**
 * Context of a notification publishing operation.
 *
 * @param destination      The destination to publish to.
 * @param template         The template. {@code null} when no template is configured.
 * @param templateMimeType MIME type of the template. {@code null} when no template is configured.
 * @param templateRenderer The template renderer.
 * @param ruleConfig       Configuration of the corresponding notification rule.
 * @since 5.7.0
 */
public record PublishContext(
        String destination,
        String template,
        String templateMimeType,
        TemplateRenderer templateRenderer,
        NotificationRuleConfig ruleConfig) {
}
