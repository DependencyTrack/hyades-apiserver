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
package org.dependencytrack.integrations.gitlab;

import alpine.Config;
import alpine.event.framework.Event;
import alpine.model.OidcUser;
import alpine.server.auth.DefaultOidcAuthenticationCustomizer;
import alpine.server.auth.OidcProfile;

import java.util.Collections;
import java.util.List;
import java.util.Objects;

import org.dependencytrack.event.GitLabSyncEvent;
import org.dependencytrack.persistence.QueryManager;

import com.nimbusds.openid.connect.sdk.claims.ClaimsSet;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import net.minidev.json.JSONObject;

public class GitLabAuthenticationCustomizer extends DefaultOidcAuthenticationCustomizer {

    @Override
    public OidcProfile createProfile(ClaimsSet claimsSet) {
        final String teamsClaimName = Config.getInstance().getProperty(Config.AlpineKey.OIDC_TEAMS_CLAIM);
        String usernameClaimName = Config.getInstance().getProperty(Config.AlpineKey.OIDC_USERNAME_CLAIM);
        final var profile = new OidcProfile();

        if (claimsSet.getStringClaim("user_login") != null)
            usernameClaimName = "user_login";

        profile.setSubject(Objects.requireNonNullElse(claimsSet.getStringClaim("user_id"),
                claimsSet.getStringClaim(UserInfo.SUB_CLAIM_NAME)));
        profile.setUsername(claimsSet.getStringClaim(usernameClaimName));
        profile.setEmail(Objects.requireNonNullElse(claimsSet.getStringClaim("user_email"),
                claimsSet.getStringClaim(UserInfo.EMAIL_CLAIM_NAME)));

        JSONObject claimsObj = claimsSet.toJSONObject();
        claimsObj.remove(UserInfo.EMAIL_CLAIM_NAME);
        claimsObj.remove(UserInfo.SUB_CLAIM_NAME);
        claimsObj.remove(teamsClaimName);
        claimsObj.remove(usernameClaimName);

        profile.setCustomValues(claimsObj);

        return profile;
    }

    @Override
    public OidcUser onAuthenticationSuccess(OidcUser user, OidcProfile profile, String idToken, String accessToken) {
        try (final QueryManager qm = new QueryManager()) {
            final List<String> groups = Objects.requireNonNullElse(profile.getGroups(), Collections.emptyList());

            groups.stream()
                    .filter(Objects::nonNull)
                    .filter(group -> qm.getOidcGroup(group) == null)
                    .forEach(qm::createOidcGroup);
        }

        Event.dispatch(new GitLabSyncEvent(accessToken, user));

        return user;
    }

}
