package org.dependencytrack.policy.cel;

import com.google.api.expr.v1alpha1.Type;
import org.apache.commons.collections4.MultiValuedMap;
import org.projectnessie.cel.Program;
import org.projectnessie.cel.common.types.Err;
import org.projectnessie.cel.common.types.ref.Val;
import org.projectnessie.cel.tools.ScriptExecutionException;

import java.util.Map;

public class CelPolicyScript {

    private final Program program;
    private final MultiValuedMap<Type, String> requirements;

    CelPolicyScript(final Program program, final MultiValuedMap<Type, String> requirements) {
        this.program = program;
        this.requirements = requirements;
    }

    public MultiValuedMap<Type, String> getRequirements() {
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
