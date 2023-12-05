package org.dependencytrack.policy.cel;

import org.projectnessie.cel.EnvOption;
import org.projectnessie.cel.Library;
import org.projectnessie.cel.ProgramOption;

import java.util.Collections;
import java.util.List;

class CelComponentPolicyLibrary implements Library {

    @Override
    public List<EnvOption> getCompileOptions() {
        return List.of(
                EnvOption.declarations(
                        CelPolicyVariable.COMPONENT.declaration(),
                        CelPolicyVariable.PROJECT.declaration(),
                        CelPolicyVariable.VULNS.declaration(),
                        CelPolicyVariable.NOW.declaration()
                )
        );
    }

    @Override
    public List<ProgramOption> getProgramOptions() {
        return Collections.emptyList();
    }

}
