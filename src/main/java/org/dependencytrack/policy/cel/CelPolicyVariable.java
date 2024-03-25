package org.dependencytrack.policy.cel;

import com.google.api.expr.v1alpha1.Decl;
import com.google.api.expr.v1alpha1.Type;
import org.dependencytrack.policy.cel.definition.CelPolicyTypes;
import org.projectnessie.cel.checker.Decls;

enum CelPolicyVariable {

    COMPONENT("component", CelPolicyTypes.TYPE_COMPONENT),
    PROJECT("project", CelPolicyTypes.TYPE_PROJECT),
    VULN("vuln", CelPolicyTypes.TYPE_VULNERABILITY),
    VULNS("vulns", CelPolicyTypes.TYPE_VULNERABILITIES),
    NOW("now", Decls.Timestamp);

    private final String name;
    private final Type type;

    CelPolicyVariable(final String name, final Type type) {
        this.name = name;
        this.type = type;
    }

    String variableName() {
        return name;
    }

    Decl declaration() {
        return Decls.newVar(name, type);
    }

}
