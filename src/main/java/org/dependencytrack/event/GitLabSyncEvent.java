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
package org.dependencytrack.event;

import alpine.event.framework.UnblockedEvent;
import alpine.model.OidcUser;

/**
 * Defines an event used to start a sync task of current user's GitLab groups.
 *
 * @author Jonathan Howard
 */
public class GitLabSyncEvent implements UnblockedEvent {

    private String accessToken;
    private OidcUser user;

    public GitLabSyncEvent() {

    }

    public GitLabSyncEvent(final String accessToken, final OidcUser user) {
        this.accessToken = accessToken;
        this.user = user;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(final String accessToken) {
        this.accessToken = accessToken;
    }

    public OidcUser getUser() {
        return user;
    }

    public void setUser(OidcUser user) {
        this.user = user;
    }

    @Override
    public String toString() {
        return "%s{accessToken=%s, user=%s}".formatted(getClass().getName(), accessToken, user);
    }

}
