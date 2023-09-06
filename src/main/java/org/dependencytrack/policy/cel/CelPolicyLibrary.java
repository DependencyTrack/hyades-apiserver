package org.dependencytrack.policy.cel;

import com.google.api.expr.v1alpha1.Type;
import org.dependencytrack.proto.policy.v1.Component;
import org.dependencytrack.proto.policy.v1.License;
import org.dependencytrack.proto.policy.v1.Project;
import org.dependencytrack.proto.policy.v1.Vulnerability;
import org.projectnessie.cel.EnvOption;
import org.projectnessie.cel.Library;
import org.projectnessie.cel.ProgramOption;
import org.projectnessie.cel.checker.Decls;

import java.util.Collections;
import java.util.List;

public class CelPolicyLibrary implements Library {

    static final String VAR_COMPONENT = "component";
    static final String VAR_PROJECT = "project";
    static final String VAR_VULNERABILITIES = "vulns";

    private static final Type TYPE_COMPONENT = Decls.newObjectType(Component.getDescriptor().getFullName());
    private static final Type TYPE_PROJECT = Decls.newObjectType(Project.getDescriptor().getFullName());
    private static final Type TYPE_VULNERABILITY = Decls.newObjectType(Vulnerability.getDescriptor().getFullName());
    private static final Type TYPE_VULNERABILITIES = Decls.newListType(TYPE_VULNERABILITY);

    @Override
    public List<EnvOption> getCompileOptions() {
        return List.of(
                EnvOption.declarations(
                        Decls.newVar(
                                VAR_COMPONENT,
                                TYPE_COMPONENT
                        ),
                        Decls.newVar(
                                VAR_PROJECT,
                                TYPE_PROJECT
                        ),
                        Decls.newVar(
                                VAR_VULNERABILITIES,
                                TYPE_VULNERABILITIES
                        )
                ),
                EnvOption.types(
                        Component.getDefaultInstance(),
                        License.getDefaultInstance(),
                        Project.getDefaultInstance(),
                        Vulnerability.getDefaultInstance(),
                        Vulnerability.Alias.getDefaultInstance()
                )
        );
    }

    @Override
    public List<ProgramOption> getProgramOptions() {
        return Collections.emptyList();
    }

}
