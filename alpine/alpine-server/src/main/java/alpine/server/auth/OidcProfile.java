/*
 * This file is part of Alpine.
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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */

package alpine.server.auth;

import java.util.List;

/**
 * @since 1.10.0
 */
class OidcProfile {

    private String subject;
    private String username;
    private List<String> groups;
    private String email;

    String getSubject() {
        return subject;
    }

    void setSubject(final String subject) {
        this.subject = subject;
    }

    String getUsername() {
        return username;
    }

    void setUsername(final String username) {
        this.username = username;
    }

    List<String> getGroups() {
        return groups;
    }

    void setGroups(final List<String> groups) {
        this.groups = groups;
    }

    String getEmail() {
        return email;
    }

    void setEmail(final String email) {
        this.email = email;
    }

    @Override
    public String toString() {
        return "OidcProfile{" +
                "subject='" + subject + '\'' +
                ", username='" + username + '\'' +
                ", groups=" + groups +
                ", email='" + email + '\'' +
                '}';
    }

}
