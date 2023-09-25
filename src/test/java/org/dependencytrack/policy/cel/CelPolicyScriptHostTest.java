package org.dependencytrack.policy.cel;

import alpine.server.cache.AbstractCacheManager;
import com.google.api.expr.v1alpha1.Type;
import org.apache.commons.codec.digest.DigestUtils;
import org.dependencytrack.policy.cel.CelPolicyScriptHost.CacheMode;
import org.junit.Test;

import java.util.Collection;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.policy.cel.CelPolicyLibrary.TYPE_COMPONENT;
import static org.dependencytrack.policy.cel.CelPolicyLibrary.TYPE_LICENSE;
import static org.dependencytrack.policy.cel.CelPolicyLibrary.TYPE_LICENSE_GROUP;
import static org.dependencytrack.policy.cel.CelPolicyLibrary.TYPE_PROJECT;
import static org.dependencytrack.policy.cel.CelPolicyLibrary.TYPE_VULNERABILITY;

public class CelPolicyScriptHostTest {

    private static class TestCacheManager extends AbstractCacheManager {

        private TestCacheManager() {
            super(30, TimeUnit.SECONDS, 5);
        }

    }

    @Test
    public void testCompileWithCache() throws Exception {
        final var scriptSrc = """
                component.name == "foo"
                """;

        final var cacheManager = new TestCacheManager();
        final CelPolicyScript script = new CelPolicyScriptHost(cacheManager).compile("""
                component.name == "foo"
                """, CacheMode.CACHE);

        assertThat((Object) cacheManager.get(CelPolicyScript.class, DigestUtils.sha256Hex(scriptSrc))).isEqualTo(script);
    }

    @Test
    public void testCompileWithoutCache() throws Exception {
        final var scriptSrc = """
                component.name == "foo"
                """;

        final var cacheManager = new TestCacheManager();
        new CelPolicyScriptHost(cacheManager).compile("""
                component.name == "foo"
                """, CacheMode.NO_CACHE);

        assertThat((Object) cacheManager.get(CelPolicyScript.class, DigestUtils.sha256Hex(scriptSrc))).isNull();
    }

    @Test
    public void testRequirementsAnalysis() throws Exception {
        final CelPolicyScript compiledScript = CelPolicyScriptHost.getInstance().compile("""
                component.resolved_license.groups.exists(licenseGroup, licenseGroup.name == "Permissive")
                  && vulns.exists(vuln, vuln.severity in ["HIGH", "CRITICAL"] && has(vuln.aliases))
                  && project.depends_on(org.hyades.policy.v1.Component{name: "foo"})
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

}