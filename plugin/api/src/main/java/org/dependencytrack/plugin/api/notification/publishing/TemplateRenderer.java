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

import org.dependencytrack.proto.notification.v1.Notification;

import java.util.Map;

/**
 * @since 5.7.0
 */
public interface TemplateRenderer {

    /**
     * Render the template for the given notification.
     *
     * @param notification      The notification to render the template for.
     * @param additionalContext Optional additional template context.
     * @return The rendered template.
     */
    byte[] render(Notification notification, Map<String, Object> additionalContext);

    /**
     * Render the template for the given notification without additional context.
     *
     * @see #render(Notification, Map)
     */
    default byte[] render(Notification notification) {
        return render(notification, null);
    }

}
