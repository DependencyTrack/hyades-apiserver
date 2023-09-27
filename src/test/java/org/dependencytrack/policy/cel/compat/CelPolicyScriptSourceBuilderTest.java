package org.dependencytrack.policy.cel.compat;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.policy.cel.compat.CelPolicyScriptSourceBuilder.escapeQuotes;

public class CelPolicyScriptSourceBuilderTest {

    @Test
    public void testEscapeQuotes() {
        assertThat(escapeQuotes("\"foobar")).isEqualTo("\\\"foobar");
    }

}