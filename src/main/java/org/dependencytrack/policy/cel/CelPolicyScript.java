package org.dependencytrack.policy.cel;

import org.projectnessie.cel.Program;
import org.projectnessie.cel.common.types.Err;
import org.projectnessie.cel.common.types.ref.Val;
import org.projectnessie.cel.tools.ScriptExecutionException;

import java.util.Map;
import java.util.Set;

public class CelPolicyScript {

    public enum Requirement {
        LICENSE,
        LICENSE_GROUPS,
        PROJECT,
        PROJECT_PROPERTIES,
        VULNERABILITIES,
        VULNERABILITY_ALIASES
    }

    private final Program program;
    private final Set<Requirement> requirements;

    public CelPolicyScript(final Program program, final Set<Requirement> requirements) {
        this.program = program;
        this.requirements = requirements;
    }

    public Set<Requirement> getRequirements() {
        return requirements;
    }

    public boolean execute(final Map<String, Object> arguments) throws ScriptExecutionException {
        final Val result = program.eval(arguments).getVal();

        if (Err.isError(result)) {
            final Err error = (Err) result;
            throw new ScriptExecutionException(error.toString(), error.getCause());
        }

        return result.convertToNative(Boolean.class);
    }

}
