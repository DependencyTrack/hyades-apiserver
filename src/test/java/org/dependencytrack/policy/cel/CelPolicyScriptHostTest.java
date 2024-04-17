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
package org.dependencytrack.policy.cel;

import com.google.api.expr.v1alpha1.Type;
import org.apache.commons.codec.digest.DigestUtils;
import org.dependencytrack.TestCacheManager;
import org.dependencytrack.policy.cel.CelPolicyScriptHost.CacheMode;
import org.junit.Test;
import org.projectnessie.cel.tools.ScriptCreateException;

import java.util.Collection;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.policy.cel.definition.CelPolicyTypes.TYPE_COMPONENT;
import static org.dependencytrack.policy.cel.definition.CelPolicyTypes.TYPE_LICENSE;
import static org.dependencytrack.policy.cel.definition.CelPolicyTypes.TYPE_LICENSE_GROUP;
import static org.dependencytrack.policy.cel.definition.CelPolicyTypes.TYPE_PROJECT;
import static org.dependencytrack.policy.cel.definition.CelPolicyTypes.TYPE_VULNERABILITY;
import static org.junit.Assert.assertThrows;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

public class CelPolicyScriptHostTest {

    @Test
    public void testCompileWithCache() throws Exception {
        final var scriptSrc = """
                component.name == "foo"
                """;

        final var cacheManager = new TestCacheManager(30, TimeUnit.SECONDS, 5);
        final CelPolicyScript script = new CelPolicyScriptHost(cacheManager, CelPolicyType.COMPONENT).compile("""
                component.name == "foo"
                """, CacheMode.CACHE);

        assertThat((Object) cacheManager.get(CelPolicyScript.class, DigestUtils.sha256Hex(scriptSrc))).isEqualTo(script);
    }

    @Test
    public void testCompileWithoutCache() throws Exception {
        final var scriptSrc = """
                component.name == "foo"
                """;

        final var cacheManager = new TestCacheManager(30, TimeUnit.SECONDS, 5);
        new CelPolicyScriptHost(cacheManager, CelPolicyType.COMPONENT).compile("""
                component.name == "foo"
                """, CacheMode.NO_CACHE);

        assertThat((Object) cacheManager.get(CelPolicyScript.class, DigestUtils.sha256Hex(scriptSrc))).isNull();
    }

    @Test
    public void testRequirementsAnalysis() throws Exception {
        final CelPolicyScript compiledScript = CelPolicyScriptHost.getInstance(CelPolicyType.COMPONENT).compile("""
                component.resolved_license.groups.exists(licenseGroup, licenseGroup.name == "Permissive")
                  && vulns.exists(vuln, vuln.severity in ["HIGH", "CRITICAL"] && has(vuln.aliases))
                  && project.depends_on(v1.Component{name: "foo"})
                """, CacheMode.NO_CACHE);

        final Map<Type, Collection<String>> requirements = compiledScript.getRequirements().asMap();
        assertThat(requirements).containsOnlyKeys(TYPE_COMPONENT, TYPE_LICENSE, TYPE_LICENSE_GROUP, TYPE_PROJECT, TYPE_VULNERABILITY);

        assertThat(requirements.get(TYPE_COMPONENT)).containsOnly("resolved_license");
        assertThat(requirements.get(TYPE_LICENSE)).containsOnly("groups");
        assertThat(requirements.get(TYPE_LICENSE_GROUP)).containsOnly("name");
        assertThat(requirements.get(TYPE_PROJECT)).containsOnly("uuid"); // Implicit through project.depends_on
        assertThat(requirements.get(TYPE_VULNERABILITY)).containsOnly(
                "aliases",
                // Scores are necessary to calculate severity...
                "cvssv2_base_score",
                "cvssv3_base_score",
                "owasp_rr_likelihood_score",
                "owasp_rr_technical_impact_score",
                "owasp_rr_business_impact_score",
                "severity");
    }

    @Test
    public void testVisitVersRangeCheck() {
        var exception = assertThrows(ScriptCreateException.class, () -> CelPolicyScriptHost.getInstance(CelPolicyType.COMPONENT).compile("""
                project.name == "foo" && project.matches_range("vers:generic<1")
                  && project.depends_on(v1.Component{
                       version: "vers:maven/>0|>1"
                     })
                """, CacheMode.NO_CACHE));
        assertThat(exception.getMessage()).isEqualTo("""
                Failed to check script: ERROR: <input>:1:48: vers string does not contain a versioning scheme separator
                 | project.name == "foo" && project.matches_range("vers:generic<1")
                 | ...............................................^
                ERROR: <input>:2:37: Querying by version range without providing an additional field to filter on is not allowed. Possible fields to filter on are: [cpe, group, name, purl, swid_tag_id]
                 |   && project.depends_on(v1.Component{
                 | ....................................^
                ERROR: <input>:3:17: Invalid range vers:maven/>0|>1: A > or >= comparator must only be followed by a < or <= comparator, but got: >
                 |        version: "vers:maven/>0|>1"
                 | ................^""");

        exception = assertThrows(ScriptCreateException.class, () -> CelPolicyScriptHost.getInstance(CelPolicyType.COMPONENT).compile("""
                component.matches_range("vers:generic<1") == "foo" && project.matches_range("vers:generic<1")
                """, CacheMode.NO_CACHE));
        assertThat(exception.getMessage()).isEqualTo("""
                Failed to check script: ERROR: <input>:1:25: vers string does not contain a versioning scheme separator
                 | component.matches_range("vers:generic<1") == "foo" && project.matches_range("vers:generic<1")
                 | ........................^
                ERROR: <input>:1:77: vers string does not contain a versioning scheme separator
                 | component.matches_range("vers:generic<1") == "foo" && project.matches_range("vers:generic<1")
                 | ............................................................................^""");

        exception = assertThrows(ScriptCreateException.class, () -> CelPolicyScriptHost.getInstance(CelPolicyType.COMPONENT).compile("""
                component.name == "foo" || vulns.exists(vuln, vuln.id == "foo" && component.matches_range("versgeneric/<1"))
                """, CacheMode.NO_CACHE));
        assertThat(exception.getMessage()).isEqualTo("""
                Failed to check script: ERROR: <input>:1:91: vers string does not contain a URI scheme separator
                 | component.name == "foo" || vulns.exists(vuln, vuln.id == "foo" && component.matches_range("versgeneric/<1"))
                 | ..........................................................................................^""");

        assertDoesNotThrow(() -> CelPolicyScriptHost.getInstance(CelPolicyType.COMPONENT).compile("""
                project.matches_range("vers:generic/<1")
                """, CacheMode.NO_CACHE));
    }
}