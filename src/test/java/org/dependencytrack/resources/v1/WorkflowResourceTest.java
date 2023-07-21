package org.dependencytrack.resources.v1;

import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthenticationFilter;
import org.apache.http.HttpStatus;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.model.WorkflowState;
import org.glassfish.jersey.media.multipart.MultiPartFeature;
import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.servlet.ServletContainer;
import org.glassfish.jersey.test.DeploymentContext;
import org.glassfish.jersey.test.ServletDeploymentContext;
import org.junit.Test;

import javax.json.JsonArray;
import javax.ws.rs.core.Response;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.model.WorkflowStatus.COMPLETED;
import static org.dependencytrack.model.WorkflowStatus.PENDING;
import static org.dependencytrack.model.WorkflowStep.BOM_CONSUMPTION;
import static org.dependencytrack.model.WorkflowStep.BOM_PROCESSING;

public class WorkflowResourceTest extends ResourceTest {

    @Override
    protected DeploymentContext configureDeployment() {
        return ServletDeploymentContext.forServlet(new ServletContainer(
                        new ResourceConfig(WorkflowResource.class)
                                .register(ApiFilter.class)
                                .register(AuthenticationFilter.class)
                                .register(MultiPartFeature.class)))
                .build();
    }

    @Test
    public void getWorkflowStatusOk() {
        UUID uuid = UUID.randomUUID();
        WorkflowState workflowState1 = new WorkflowState();
        workflowState1.setParent(null);
        workflowState1.setFailureReason(null);
        workflowState1.setStep(BOM_CONSUMPTION);
        workflowState1.setStatus(COMPLETED);
        workflowState1.setToken(uuid);
        var workflowState1Persisted = qm.persist(workflowState1);

        WorkflowState workflowState2 = new WorkflowState();
        workflowState2.setParent(workflowState1Persisted);
        workflowState2.setFailureReason(null);
        workflowState2.setStep(BOM_PROCESSING);
        workflowState2.setStatus(PENDING);
        workflowState2.setToken(uuid);
        workflowState2.setStartedAt(Date.from(Instant.now()));
        workflowState2.setUpdatedAt(Date.from(Instant.now()));
        qm.persist(workflowState2);

        Response response = target(V1_WORKFLOW + "/token/" + uuid + "/status").request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);

        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_OK);
        JsonArray json = parseJsonArray(response);
        assertThat(json).isNotNull();
        assertThat(json.size()).isEqualTo(2);
        var result = json.getJsonObject(0);
        assertThat(result.getInt("id")).isEqualTo(1);
        assertThat(result.getString("token")).isEqualTo(uuid.toString());
        assertThat(result.getString("step")).isEqualTo("BOM_CONSUMPTION");
        assertThat(result.getString("status")).isEqualTo("COMPLETED");
        result = json.getJsonObject(1);
        assertThat(result.getInt("id")).isEqualTo(2);
        assertThat(result.getString("token")).isEqualTo(uuid.toString());
        assertThat(result.getString("step")).isEqualTo("BOM_PROCESSING");
        assertThat(result.getString("status")).isEqualTo("PENDING");
    }

    @Test
    public void getWorkflowStatusNotFound() {
        WorkflowState workflowState1 = new WorkflowState();
        workflowState1.setParent(null);
        workflowState1.setFailureReason(null);
        workflowState1.setStep(BOM_CONSUMPTION);
        workflowState1.setStatus(COMPLETED);
        workflowState1.setToken(UUID.randomUUID());
        qm.persist(workflowState1);

        UUID randomUuid = UUID.randomUUID();
        Response response = target(V1_WORKFLOW + "/token/" + randomUuid + "/status").request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);

        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_NOT_FOUND);
        assertThat(getPlainTextBody(response)).isEqualTo("Provided token " + randomUuid + " does not exist.");
    }
}
