package org.dependencytrack.policy.validation;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.networknt.schema.JsonSchema;
import com.networknt.schema.JsonSchemaFactory;
import com.networknt.schema.SpecVersion;
import com.networknt.schema.ValidationMessage;
import org.junit.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.assertTrue;
import static org.testcontainers.shaded.org.apache.commons.io.IOUtils.resourceToString;

public class PolicySchemaValidationTest {

    @Test
    public void testValidPolicyYamlWithSchema() throws IOException {
        ObjectMapper objMapper = new ObjectMapper(new YAMLFactory());
        final String jsonSchemaContent = resourceToString("/schema/vulnerability-policy-v1.schema.json", StandardCharsets.UTF_8);
        final String policyContent = resourceToString("/unit/policy/vulnerability-policy-v1-valid.yaml", StandardCharsets.UTF_8);
        JsonSchemaFactory factory = JsonSchemaFactory.builder(JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V202012)).objectMapper(objMapper).build();
        JsonSchema schema = factory.getSchema(jsonSchemaContent);
        JsonNode jsonNode = objMapper.readTree(policyContent);
        Set<ValidationMessage> validateMsg = schema.validate(jsonNode);
        assertTrue(validateMsg.isEmpty());
    }

    @Test
    public void testInvalidPolicyYamlWithSchema() throws IOException {
        ObjectMapper objMapper = new ObjectMapper(new YAMLFactory());
        final String jsonSchemaContent = resourceToString("/schema/vulnerability-policy-v1.schema.json", StandardCharsets.UTF_8);
        final String policyContent = resourceToString("/unit/policy/vulnerability-policy-v1-invalid.yaml", StandardCharsets.UTF_8);
        JsonSchemaFactory factory = JsonSchemaFactory.builder(JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V202012)).objectMapper(objMapper).build();
        JsonSchema schema = factory.getSchema(jsonSchemaContent);
        JsonNode jsonNode = objMapper.readTree(policyContent);
        Set<ValidationMessage> validateMsg = schema.validate(jsonNode);
        assertThat(validateMsg).satisfiesExactlyInAnyOrder(
                error -> assertThat(error.getMessage()).isEqualTo("$.analysis.justification: does not have a value in the enumeration [CODE_NOT_PRESENT, CODE_NOT_REACHABLE, REQUIRES_CONFIGURATION, REQUIRES_DEPENDENCY, REQUIRES_ENVIRONMENT, PROTECTED_BY_COMPILER, PROTECTED_AT_RUNTIME, PROTECTED_AT_PERIMETER, PROTECTED_BY_MITIGATING_CONTROL]"),
                error -> assertThat(error.getMessage()).isEqualTo("$.ratings[0].severity: does not have a value in the enumeration [CRITICAL, HIGH, MEDIUM, LOW, INFO, UNASSIGNED]"),
                error -> assertThat(error.getMessage()).contains("$.ratings[0].vector: does not match the regex pattern"),
                error -> assertThat(error.getMessage()).isEqualTo("$.ratings[0].score: string found, number expected")
        );
    }
}
