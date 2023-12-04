package org.dependencytrack.policy.cel;

import com.google.api.expr.v1alpha1.Decl;
import com.google.api.expr.v1alpha1.Type;
import org.dependencytrack.proto.policy.v1.Component;
import org.dependencytrack.proto.policy.v1.Project;
import org.dependencytrack.proto.policy.v1.Vulnerability;
import org.projectnessie.cel.checker.Decls;

enum CelPolicyVariable {

    COMPONENT("component", Decls.newObjectType(Component.getDescriptor().getFullName())),
    PROJECT("project", Decls.newObjectType(Project.getDescriptor().getFullName())),
    VULN("vuln", Decls.newObjectType(Vulnerability.getDescriptor().getFullName())),
    VULNS("vulns", Decls.newListType(Decls.newObjectType(Vulnerability.getDescriptor().getFullName()))),
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
