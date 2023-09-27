package org.dependencytrack.resources.v1;

import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthenticationFilter;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.servlet.ServletContainer;
import org.glassfish.jersey.test.DeploymentContext;
import org.glassfish.jersey.test.ServletDeploymentContext;
import org.junit.Test;

import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;

public class PolicyConditionResourceTest extends ResourceTest {

    @Override
    protected DeploymentContext configureDeployment() {
        return ServletDeploymentContext.forServlet(new ServletContainer(
                        new ResourceConfig(PolicyConditionResource.class)
                                .register(ApiFilter.class)
                                .register(AuthenticationFilter.class)))
                .build();
    }

    @Test
    public void testCreateExpressionCondition() {
        final Policy policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);

        final Response response = target("%s/%s/condition".formatted(V1_POLICY, policy.getUuid()))
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("""
                        {
                          "subject": "EXPRESSION",
                          "value": "component.name == \\"foo\\"",
                          "violationType": "SECURITY"
                        }
                        """, MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(201);
        assertThatJson(getPlainTextBody(response))
                .isEqualTo("""
                        {
                          "uuid": "${json-unit.any-string}",
                          "subject": "EXPRESSION",
                          "operator": "MATCHES",
                          "value": "component.name == \\"foo\\"",
                          "violationType": "SECURITY"
                        }
                        """);
    }

    @Test
    public void testCreateExpressionConditionWithError() {
        final Policy policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);

        final Response response = target("%s/%s/condition".formatted(V1_POLICY, policy.getUuid()))
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("""
                        {
                          "subject": "EXPRESSION",
                          "value": "component.doesNotExist == \\"foo\\"",
                          "violationType": "SECURITY"
                        }
                        """, MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(400);
        assertThatJson(getPlainTextBody(response))
                .isEqualTo("""
                        {
                          "celErrors": [
                            {
                              "line": 1,
                              "column": 9,
                              "message": "undefined field 'doesNotExist'"
                            }
                          ]
                        }
                        """);
    }

    @Test
    public void testUpdateExpressionCondition() {
        final Policy policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        final PolicyCondition condition = qm.createPolicyCondition(policy,
                PolicyCondition.Subject.VULNERABILITY_ID, PolicyCondition.Operator.IS, "foobar");

        final Response response = target("%s/condition".formatted(V1_POLICY))
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity("""
                        {
                          "uuid": "%s",
                          "subject": "EXPRESSION",
                          "value": "component.name == \\"foo\\"",
                          "violationType": "OPERATIONAL"
                        }
                        """.formatted(condition.getUuid()), MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(201);
        assertThatJson(getPlainTextBody(response))
                .isEqualTo("""
                        {
                          "uuid": "${json-unit.any-string}",
                          "subject": "EXPRESSION",
                          "operator": "MATCHES",
                          "value": "component.name == \\"foo\\"",
                          "violationType": "OPERATIONAL"
                        }
                        """);
    }

    @Test
    public void testUpdateExpressionConditionWithError() {
        final Policy policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        final PolicyCondition condition = qm.createPolicyCondition(policy,
                PolicyCondition.Subject.VULNERABILITY_ID, PolicyCondition.Operator.IS, "foobar");

        final Response response = target("%s/condition".formatted(V1_POLICY))
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity("""
                        {
                          "uuid": "%s",
                          "subject": "EXPRESSION",
                          "value": "component.doesNotExist == \\"foo\\"",
                          "violationType": "SECURITY"
                        }
                        """.formatted(condition.getUuid()), MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(400);
        assertThatJson(getPlainTextBody(response))
                .isEqualTo("""
                        {
                          "celErrors": [
                            {
                              "line": 1,
                              "column": 9,
                              "message": "undefined field 'doesNotExist'"
                            }
                          ]
                        }
                        """);
    }

}