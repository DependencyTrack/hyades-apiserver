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
package org.dependencytrack.resources;

import alpine.server.auth.PermissionRequired;
import alpine.server.filters.ProjectAccessFiltered;
import com.tngtech.archunit.base.DescribedPredicate;
import com.tngtech.archunit.core.domain.JavaMethod;
import com.tngtech.archunit.core.importer.ImportOption.DoNotIncludeJars;
import com.tngtech.archunit.core.importer.ImportOption.DoNotIncludeTests;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchCondition;
import com.tngtech.archunit.lang.ArchRule;
import com.tngtech.archunit.lang.ConditionEvents;
import com.tngtech.archunit.lang.SimpleConditionEvent;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.PATCH;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
import org.dependencytrack.auth.Permissions;

import java.lang.annotation.Annotation;
import java.util.List;
import java.util.Set;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.methods;

@AnalyzeClasses(
        packages = "org.dependencytrack.resources",
        importOptions = {
                DoNotIncludeJars.class,
                DoNotIncludeTests.class,
        })
class ResourceAuthorizationArchitectureTest {

    private static final List<Class<? extends Annotation>> HTTP_METHOD_ANNOTATIONS =
            List.of(GET.class, POST.class, PUT.class, DELETE.class, PATCH.class);

    /**
     * Permissions that can be scoped to individual projects.
     * Only these should be combined with {@link ProjectAccessFiltered}.
     */
    private static final Set<String> PROJECT_SCOPABLE_PERMISSIONS = Set.of(
            Permissions.Constants.BOM_UPLOAD,
            Permissions.Constants.POLICY_VIOLATION_ANALYSIS,
            Permissions.Constants.PORTFOLIO_MANAGEMENT,
            Permissions.Constants.PORTFOLIO_MANAGEMENT_CREATE,
            Permissions.Constants.PORTFOLIO_MANAGEMENT_DELETE,
            Permissions.Constants.PORTFOLIO_MANAGEMENT_READ,
            Permissions.Constants.PORTFOLIO_MANAGEMENT_UPDATE,
            Permissions.Constants.PROJECT_CREATION_UPLOAD,
            Permissions.Constants.VIEW_POLICY_VIOLATION,
            Permissions.Constants.VIEW_PORTFOLIO,
            Permissions.Constants.VIEW_VULNERABILITY,
            Permissions.Constants.VULNERABILITY_ANALYSIS,
            Permissions.Constants.VULNERABILITY_ANALYSIS_CREATE,
            Permissions.Constants.VULNERABILITY_ANALYSIS_READ,
            Permissions.Constants.VULNERABILITY_ANALYSIS_UPDATE);

    /**
     * Endpoints that intentionally skip authorization. These are either public
     * (e.g. OpenAPI spec) or require only authentication.
     */
    private static final Set<String> AUTHORIZATION_EXEMPT_METHODS = Set.of(
            "org.dependencytrack.resources.v1.BadgeResource.getProjectPolicyViolationsBadge(java.lang.String)",
            "org.dependencytrack.resources.v1.BadgeResource.getProjectPolicyViolationsBadge(java.lang.String, java.lang.String)",
            "org.dependencytrack.resources.v1.BadgeResource.getProjectVulnerabilitiesBadge(java.lang.String)",
            "org.dependencytrack.resources.v1.BadgeResource.getProjectVulnerabilitiesBadge(java.lang.String, java.lang.String)",
            "org.dependencytrack.resources.v1.CalculatorResource.getCvssScores(java.lang.String)",
            "org.dependencytrack.resources.v1.CalculatorResource.getOwaspRRScores(java.lang.String)",
            "org.dependencytrack.resources.v1.ConfigPropertyResource.getPublicConfigProperty(java.lang.String, java.lang.String)",
            "org.dependencytrack.resources.v1.CweResource.getCwe(int)",
            "org.dependencytrack.resources.v1.CweResource.getCwes()",
            "org.dependencytrack.resources.v1.EventResource.isTokenBeingProcessed(java.lang.String)",
            "org.dependencytrack.resources.v1.LicenseResource.getLicense(java.lang.String)",
            "org.dependencytrack.resources.v1.LicenseResource.getLicenseListing()",
            "org.dependencytrack.resources.v1.LicenseResource.getLicenses()",
            "org.dependencytrack.resources.v1.OidcResource.isAvailable()",
            "org.dependencytrack.resources.v1.OpenApiResource.getOpenApi(jakarta.ws.rs.core.HttpHeaders, jakarta.ws.rs.core.UriInfo, java.lang.String)",
            "org.dependencytrack.resources.v1.RepositoryResource.getRepositoryMetaComponent(java.lang.String)",
            "org.dependencytrack.resources.v1.TeamResource.availableTeams()",
            "org.dependencytrack.resources.v1.TeamResource.getSelf()",
            "org.dependencytrack.resources.v1.UserResource.forceChangePassword(java.lang.String, java.lang.String, java.lang.String, java.lang.String)",
            "org.dependencytrack.resources.v1.UserResource.getSelf()",
            "org.dependencytrack.resources.v1.UserResource.getSelfPermissions()",
            "org.dependencytrack.resources.v1.UserResource.logout(java.lang.String)",
            "org.dependencytrack.resources.v1.UserResource.updateSelf(alpine.model.ManagedUser)",
            "org.dependencytrack.resources.v1.UserResource.validateCredentials(java.lang.String, java.lang.String)",
            "org.dependencytrack.resources.v1.UserResource.validateOidcAccessToken(java.lang.String, java.lang.String)",
            "org.dependencytrack.resources.v2.OpenApiResource.getOpenApi()");

    @ArchTest
    static final ArchRule httpMethodsMustRequirePermission =
            methods()
                    .that(areHttpEndpoints())
                    .and(areNotExemptFromAuthorization())
                    .should().beAnnotatedWith(PermissionRequired.class)
                    .because("""
                            Every JAX-RS endpoint must declare required permissions via \
                            @PermissionRequired. Endpoints without this annotation bypass \
                            the AuthorizationFilter entirely. If an endpoint intentionally \
                            requires no permissions, add it to AUTHORIZATION_EXEMPT_METHODS.""");

    private static DescribedPredicate<JavaMethod> areHttpEndpoints() {
        return new DescribedPredicate<>("are annotated with a JAX-RS HTTP method annotation") {
            @Override
            public boolean test(JavaMethod method) {
                return HTTP_METHOD_ANNOTATIONS.stream().anyMatch(method::isAnnotatedWith);
            }
        };
    }

    private static DescribedPredicate<JavaMethod> areNotExemptFromAuthorization() {
        return new DescribedPredicate<>("are not exempt from authorization") {
            @Override
            public boolean test(JavaMethod method) {
                return !AUTHORIZATION_EXEMPT_METHODS.contains(method.getFullName());
            }
        };
    }

    @ArchTest
    static final ArchRule projectAccessFilteredMustBePairedWithPermissionRequired =
            methods()
                    .that().areAnnotatedWith(ProjectAccessFiltered.class)
                    .should().beAnnotatedWith(PermissionRequired.class)
                    .because("""
                            @ProjectAccessFiltered requires @PermissionRequired so that the \
                            AuthorizationFilter can verify the principal holds the required \
                            permission at either global or project scope.""");

    @ArchTest
    static final ArchRule projectAccessFilteredMustBeInAbstractApiResource =
            methods()
                    .that().areAnnotatedWith(ProjectAccessFiltered.class)
                    .should(new ArchCondition<>("be declared in an AbstractApiResource subclass") {
                        @Override
                        public void check(JavaMethod method, ConditionEvents events) {
                            if (!method.getOwner().isAssignableTo(AbstractApiResource.class)) {
                                events.add(SimpleConditionEvent.violated(method, """
                                        %s is not in an AbstractApiResource subclass\
                                        """.formatted(method.getFullName())));
                            }
                        }
                    })
                    .because("""
                            @ProjectAccessFiltered may only be used on methods in AbstractApiResource \
                            subclasses, which provide requireAccess() and requireProjectAccess() \
                            for enforcing project-level ACLs.""");

    @ArchTest
    static final ArchRule projectAccessFilteredMustUseProjectScopablePermissions =
            methods()
                    .that().areAnnotatedWith(ProjectAccessFiltered.class)
                    .should(new ArchCondition<>("only require project-scopable permissions") {
                        @Override
                        public void check(JavaMethod method, ConditionEvents events) {
                            if (!method.isAnnotatedWith(PermissionRequired.class)) {
                                return;
                            }

                            final String[] values = method.getAnnotationOfType(PermissionRequired.class).value();

                            for (final String perm : values) {
                                if (!PROJECT_SCOPABLE_PERMISSIONS.contains(perm)) {
                                    events.add(SimpleConditionEvent.violated(method, """
                                            %s uses @ProjectAccessFiltered with non-project-scopable \
                                            permission %s""".formatted(method.getFullName(), perm)));
                                }
                            }
                        }
                    })
                    .because("""
                            @ProjectAccessFiltered tells the AuthorizationFilter to accept \
                            project-scoped permissions. Permissions like SYSTEM_CONFIGURATION \
                            or ACCESS_MANAGEMENT are never project-scoped and must not be \
                            combined with this annotation.""");

}
