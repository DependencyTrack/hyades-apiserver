package org.dependencytrack.persistence.jdbi.mapping;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsonorg.JsonOrgModule;
import org.dependencytrack.policy.vulnerability.VulnerabilityPolicyAnalysis;
import org.jdbi.v3.core.argument.AbstractArgumentFactory;
import org.jdbi.v3.core.argument.Argument;
import org.jdbi.v3.core.config.ConfigRegistry;

import java.sql.Types;

public class VulnPolicyAnalysisArgumentFactory extends AbstractArgumentFactory<VulnerabilityPolicyAnalysis> {

    private static final ObjectMapper MAPPER = new ObjectMapper().registerModule(new JsonOrgModule());
    public VulnPolicyAnalysisArgumentFactory() {
        super(Types.VARCHAR);
    }

    @Override
    protected Argument build(VulnerabilityPolicyAnalysis vulnerabilityPolicyAnalysis, ConfigRegistry config) {
        try {
            String analysis = vulnerabilityPolicyAnalysis != null
                    ? MAPPER.writeValueAsString(vulnerabilityPolicyAnalysis)
                    : null;
            return (position, statement, ctx) -> statement.setString(position, analysis);
        } catch(JsonProcessingException ex) {
            return (position, statement, ctx) -> statement.setString(position, null);
        }
    }
}
