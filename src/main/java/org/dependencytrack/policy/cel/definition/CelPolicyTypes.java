package org.dependencytrack.policy.cel.definition;

import com.google.api.expr.v1alpha1.Type;
import org.dependencytrack.proto.policy.v1.Component;
import org.dependencytrack.proto.policy.v1.License;
import org.dependencytrack.proto.policy.v1.Project;
import org.dependencytrack.proto.policy.v1.Vulnerability;
import org.projectnessie.cel.checker.Decls;

public class CelPolicyTypes {

    public static final Type TYPE_COMPONENT = Decls.newObjectType(Component.getDescriptor().getFullName());
    public static final Type TYPE_LICENSE = Decls.newObjectType(License.getDescriptor().getFullName());
    public static final Type TYPE_LICENSE_GROUP = Decls.newObjectType(License.Group.getDescriptor().getFullName());
    public static final Type TYPE_PROJECT = Decls.newObjectType(Project.getDescriptor().getFullName());
    public static final Type TYPE_PROJECT_PROPERTY = Decls.newObjectType(Project.Property.getDescriptor().getFullName());
    public static final Type TYPE_VULNERABILITY = Decls.newObjectType(Vulnerability.getDescriptor().getFullName());
    public static final Type TYPE_VULNERABILITIES = Decls.newListType(TYPE_VULNERABILITY);
    public static final Type TYPE_VULNERABILITY_ALIAS = Decls.newObjectType(Vulnerability.Alias.getDescriptor().getFullName());

}
