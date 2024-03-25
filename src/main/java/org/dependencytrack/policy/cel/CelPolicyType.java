package org.dependencytrack.policy.cel;

import org.projectnessie.cel.EnvOption;
import org.projectnessie.cel.Library;
import org.projectnessie.cel.extension.StringsLib;

import java.util.List;

public enum CelPolicyType {

    COMPONENT(List.of(
            Library.StdLib(),
            Library.Lib(new StringsLib()),
            Library.Lib(new CelComponentPolicyLibrary()),
            Library.Lib(new CelCommonPolicyLibrary())
    )),
    VULNERABILITY(List.of(
            Library.StdLib(),
            Library.Lib(new StringsLib()),
            Library.Lib(new CelVulnerabilityPolicyLibrary()),
            Library.Lib(new CelCommonPolicyLibrary())
    ));

    private final List<EnvOption> envOptions;

    CelPolicyType(final List<EnvOption> envOptions) {
        this.envOptions = envOptions;
    }

    List<EnvOption> envOptions() {
        return envOptions;
    }

}
