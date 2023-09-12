package org.dependencytrack.policy.cel;

import com.google.api.expr.v1alpha1.Type;
import org.junit.Test;

import java.util.Collection;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.policy.cel.CelPolicyLibrary.TYPE_COMPONENT;
import static org.dependencytrack.policy.cel.CelPolicyLibrary.TYPE_LICENSE;
import static org.dependencytrack.policy.cel.CelPolicyLibrary.TYPE_LICENSE_GROUP;
import static org.dependencytrack.policy.cel.CelPolicyLibrary.TYPE_VULNERABILITY;

public class CelPolicyScriptHostTest {

    @Test
    public void testRequirements() throws Exception {
        final CelPolicyScript compiledScript = CelPolicyScriptHost.getInstance().compile("""
                component.resolved_license.groups.exists(licenseGroup, licenseGroup.name == "Permissive")
                  && vulns.filter(vuln, vuln.severity in ["HIGH", "CRITICAL"]).size() > 1
                """);

        final Map<Type, Collection<String>> requirements = compiledScript.getRequirements().asMap();
        assertThat(requirements).containsKeys(TYPE_COMPONENT, TYPE_LICENSE, TYPE_LICENSE_GROUP, TYPE_VULNERABILITY);

        assertThat(requirements.get(TYPE_COMPONENT)).containsOnly("resolved_license");
        assertThat(requirements.get(TYPE_LICENSE)).containsOnly("groups");
        assertThat(requirements.get(TYPE_LICENSE_GROUP)).containsOnly("name");
        assertThat(requirements.get(TYPE_VULNERABILITY)).containsOnly("severity");
    }

}