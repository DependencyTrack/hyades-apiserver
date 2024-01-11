package org.dependencytrack.persistence.jdbi.mapping;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsonorg.JsonOrgModule;
import org.dependencytrack.policy.vulnerability.VulnerabilityPolicyRating;
import org.jdbi.v3.core.argument.AbstractArgumentFactory;
import org.jdbi.v3.core.argument.Argument;
import org.jdbi.v3.core.config.ConfigRegistry;

import java.sql.Types;
import java.util.List;

public class VulnPolicyRatingsArgumentFactory extends AbstractArgumentFactory<List<VulnerabilityPolicyRating>> {

    private static final ObjectMapper MAPPER = new ObjectMapper().registerModule(new JsonOrgModule());
    public VulnPolicyRatingsArgumentFactory() {
        super(Types.VARCHAR);
    }

    @Override
    protected Argument build(List<VulnerabilityPolicyRating> vulnerabilityPolicyRating, ConfigRegistry config) {
        try {
            String ratings = vulnerabilityPolicyRating != null
                    ? MAPPER.writeValueAsString(vulnerabilityPolicyRating)
                    : null;
            return (position, statement, ctx) -> statement.setString(position, ratings);
        } catch(JsonProcessingException ex) {
            return (position, statement, ctx) -> statement.setString(position, null);
        }
    }
}
