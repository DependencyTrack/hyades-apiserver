package org.dependencytrack.policy.validation;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.networknt.schema.JsonSchema;
import com.networknt.schema.JsonSchemaFactory;
import com.networknt.schema.SpecVersion;
import com.networknt.schema.ValidationMessage;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.assertTrue;

public class PolicySchemaValidationTest {

    @Test
    public void testValidPolicyYamlWithSchema() throws IOException {
        ObjectMapper objMapper = new ObjectMapper(new YAMLFactory());
        final File jsonSchemaFile = new File("src/main/java/org/dependencytrack/policy/validation/policySchema.json");
        final URI uri = jsonSchemaFile.toURI();
        final File yamlFile = new File("src/test/resources/policy/policyValid.yaml");
        JsonSchemaFactory factory = JsonSchemaFactory.builder(JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V202012)).objectMapper(objMapper).build();
        JsonSchema schema = factory.getSchema(uri);
        JsonNode jsonNode = objMapper.readTree(yamlFile);
        Set<ValidationMessage> validateMsg = schema.validate(jsonNode);
        assertTrue(validateMsg.isEmpty());
    }

    @Test
    public void testInvalidPolicyYamlWithSchema() throws IOException {
        ObjectMapper objMapper = new ObjectMapper(new YAMLFactory());
        final File jsonSchemaFile = new File("src/main/java/org/dependencytrack/policy/validation/policySchema.json");
        final URI uri = jsonSchemaFile.toURI();
        final File yamlFile = new File("src/test/resources/policy/policyInvalid.yaml");
        JsonSchemaFactory factory = JsonSchemaFactory.builder(JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V202012)).objectMapper(objMapper).build();
        JsonSchema schema = factory.getSchema(uri);
        JsonNode jsonNode = objMapper.readTree(yamlFile);
        Set<ValidationMessage> validateMsg = schema.validate(jsonNode);
        assertThat(validateMsg.size()).isEqualTo(5);
        assertThat(validateMsg).satisfiesExactlyInAnyOrder(
                error -> {
                    assertThat(error.getMessage()).isEqualTo("$.created: 2023-11-22T06:06Z is an invalid date-time");
                },
                error -> {
                    assertThat(error.getMessage()).isEqualTo("$.analysis.justification: does not have a value in the enumeration [CODE_NOT_PRESENT, CODE_NOT_REACHABLE, REQUIRES_CONFIGURATION, REQUIRES_DEPENDENCY, REQUIRES_ENVIRONMENT, PROTECTED_BY_COMPILER, PROTECTED_AT_RUNTIME, PROTECTED_AT_PERIMETER, PROTECTED_BY_MITIGATING_CONTROL, NOT_SET]");
                },
                error -> {
                    assertThat(error.getMessage()).isEqualTo("$.ratings[0].severity: does not have a value in the enumeration [CRITICAL, HIGH, MEDIUM, LOW, INFO, UNASSIGNED]");
                    },
                error -> {
                    assertThat(error.getMessage()).contains("$.ratings[0].vector: does not match the regex pattern");
                },
                error -> {
                    assertThat(error.getMessage()).isEqualTo("$.ratings[0].score: string found, number expected");
                }

        );
    }
}
