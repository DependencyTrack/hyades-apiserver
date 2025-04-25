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

import alpine.Config;
import alpine.common.logging.Logger;
import alpine.model.LdapUser;
import alpine.persistence.AlpineQueryManager;

import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapContext;
import java.security.Principal;
import java.util.List;

/**
 * Class that performs authentication against LDAP servers.
 *
 * @author Steve Springett
 * @since 1.0.0
 */
public class LdapAuthenticationService implements AuthenticationService {

    private static final Logger LOGGER = Logger.getLogger(LdapAuthenticationService.class);

    private final String username;
    private final String password;

    /**
     * Authentication service validates credentials against a directory service (LDAP).
     *
     * @param username the asserted username
     * @param password the asserted password
     * @since 1.0.0
     */
    public LdapAuthenticationService(final String username, final String password) {
        this.username = username;
        this.password = password;
    }

    /**
     * Returns whether the username/password combo was specified or not. In
     * this case, since the constructor requires it, this method will always
     * return true.
     *
     * @return always will return true
     * @since 1.0.0
     */
    public boolean isSpecified() {
        return true;
    }

    /**
     * Authenticates the username/password combo against the directory service
     * and returns a Principal if authentication is successful. Otherwise,
     * returns an AuthenticationException.
     *
     * @return a Principal if authentication was successful
     * @throws AlpineAuthenticationException when authentication is unsuccessful
     * @since 1.0.0
     */
    public Principal authenticate() throws AlpineAuthenticationException {
        LOGGER.debug("Attempting to authenticate user: " + username);
        if (validateCredentials()) {
            try (AlpineQueryManager qm = new AlpineQueryManager()) {
                final LdapUser user = qm.getLdapUser(username);
                if (user != null) {
                    LOGGER.debug("Attempting to authenticate user: " + username);
                    return user;
                } else if (LdapConnectionWrapper.USER_PROVISIONING) {
                    LOGGER.debug("The user (" + username + ") authenticated successfully but the account has not been provisioned");
                    return autoProvision(qm);
                } else {
                    LOGGER.debug("The user (" + username + ") is unmapped and user provisioning is not enabled");
                    throw new AlpineAuthenticationException(AlpineAuthenticationException.CauseType.UNMAPPED_ACCOUNT);
                }
            }
        } else {
            throw new AlpineAuthenticationException(AlpineAuthenticationException.CauseType.INVALID_CREDENTIALS);
        }
    }

    /**
     * Automatically creates an LdapUser, sets the value of various LDAP attributes, and
     * persists the user to the database.
     * @param qm the query manager to use
     * @return the persisted LdapUser object
     * @throws AlpineAuthenticationException if an exception occurs
     * @since 1.4.0
     */
    private LdapUser autoProvision(final AlpineQueryManager qm) throws AlpineAuthenticationException {
        LOGGER.debug("Provisioning: " + username);
        LdapUser user = null;
        final LdapConnectionWrapper ldap = new LdapConnectionWrapper();
        DirContext dirContext = null;
        try {
            dirContext = ldap.createDirContext();
            final SearchResult result = ldap.searchForSingleUsername(dirContext, username);
            if (result != null) {
                user = new LdapUser();
                user.setUsername(username);
                user.setDN(result.getNameInNamespace());
                user.setEmail(ldap.getAttribute(result, LdapConnectionWrapper.ATTRIBUTE_MAIL));
                user = qm.persist(user);
                // Dynamically assign team membership (if enabled)
                if (LdapConnectionWrapper.TEAM_SYNCHRONIZATION) {
                    final List<String> groupDNs = ldap.getGroups(dirContext, user);
                    user = qm.synchronizeTeamMembership(user, groupDNs);
                }
            } else {
                LOGGER.warn("Could not find '" + username + "' in the directory while provisioning the user. Ensure '" + Config.AlpineKey.LDAP_ATTRIBUTE_NAME.getPropertyName() + "' is defined correctly");
                throw new AlpineAuthenticationException(AlpineAuthenticationException.CauseType.UNMAPPED_ACCOUNT);
            }
        } catch (NamingException e) {
            LOGGER.error("An error occurred while auto-provisioning an authenticated user", e);
            throw new AlpineAuthenticationException(AlpineAuthenticationException.CauseType.OTHER);
        } finally {
            ldap.closeQuietly(dirContext);
        }
        return user;
    }

    /**
     * Asserts a users credentials. Returns a boolean value indicating if
     * assertion was successful or not.
     *
     * @return true if assertion was successful, false if not
     * @since 1.0.0
     */
    private boolean validateCredentials() {
        LOGGER.debug("Validating credentials for: " + username);
        final LdapConnectionWrapper ldap = new LdapConnectionWrapper();
        DirContext dirContext = null;
        LdapContext ldapContext = null;
        try (AlpineQueryManager qm = new AlpineQueryManager()) {
            final LdapUser ldapUser = qm.getLdapUser(username);
            if (ldapUser != null && ldapUser.getDN() != null && ldapUser.getDN().contains("=")) {
                ldapContext = ldap.createLdapContext(ldapUser.getDN(), password);
                LOGGER.debug("The supplied credentials are valid for: " + username);
                return true;
            } else {
                dirContext = ldap.createDirContext();
                final SearchResult result = ldap.searchForSingleUsername(dirContext, username);
                if (result != null ) {
                    ldapContext = ldap.createLdapContext(result.getNameInNamespace(), password);
                    LOGGER.debug("The supplied credentials are invalid for: " + username);
                    return true;
                }
            }
        } catch (NamingException e) {
            LOGGER.debug("An error occurred while attempting to validate credentials", e);
        } finally {
            ldap.closeQuietly(ldapContext);
            ldap.closeQuietly(dirContext);
        }
        return false;
    }

}
