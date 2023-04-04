package org.dependencytrack.health;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module;
import org.apache.http.HttpHeaders;
import org.eclipse.microprofile.health.HealthCheck;
import org.eclipse.microprofile.health.HealthCheckResponse;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.MediaType;
import java.io.IOException;
import java.util.List;

public class HealthCheckServlet extends HttpServlet {

    private List<HealthCheck> healthChecks;
    private ObjectMapper objectMapper;

    @Override
    public void init() {
        healthChecks = List.of(
                new DatabaseHealthCheck(),
                new KafkaStreamsHealthCheck()
        );

        objectMapper = new ObjectMapper()
                // HealthCheckResponse#data is of type Optional.
                // We need this module to correctly serialize Optional values.
                // https://github.com/FasterXML/jackson-modules-java8/tree/2.15/datatypes
                .registerModule(new Jdk8Module());
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        final List<HealthCheckResponse> checkResponses = healthChecks.stream()
                .map(HealthCheck::call)
                .toList();

        // The overall UP status is determined by logical conjunction of all check statuses.
        // https://download.eclipse.org/microprofile/microprofile-health-2.1/microprofile-health-spec.html#_policies_to_determine_the_overall_status
        final HealthCheckResponse.Status overallStatus = checkResponses.stream()
                .map(HealthCheckResponse::getStatus)
                .filter(HealthCheckResponse.Status.DOWN::equals)
                .findFirst()
                .orElse(HealthCheckResponse.Status.UP);

        final JsonNode responseJson = JsonNodeFactory.instance.objectNode()
                .put("status", overallStatus.name())
                .putPOJO("checks", checkResponses);

        // https://download.eclipse.org/microprofile/microprofile-health-2.1/microprofile-health-spec.html#_response_codes_and_status_mappings
        if (overallStatus == HealthCheckResponse.Status.UP) {
            resp.setStatus(200);
        } else {
            resp.setStatus(503);
        }

        final String responseStr = objectMapper.writeValueAsString(responseJson);
        resp.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON);
        resp.getWriter().write(responseStr);
    }

}
