package org.dependencytrack.resources.v1;

import alpine.server.filters.ApiFilter;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import org.apache.http.HttpStatus;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.RepositoryMetaComponent;
import org.dependencytrack.model.RepositoryType;
import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.servlet.ServletContainer;
import org.glassfish.jersey.test.DeploymentContext;
import org.glassfish.jersey.test.ServletDeploymentContext;
import org.junit.Test;

import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonReader;
import javax.ws.rs.core.Response;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

public class ComponentResourcePostgresTest extends ResourceTest {

    @Override
    protected DeploymentContext configureDeployment() {
        return ServletDeploymentContext.forServlet(new ServletContainer(
                        new ResourceConfig(ComponentResource.class)
                                .register(ApiFilter.class)))
                .build();
    }

    @Test
    public void getAllComponentsTest() throws MalformedPackageURLException {
        final Project project = prepareProject();

        final Response response = target(V1_COMPONENT + "/project/" + project.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_OK);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1000"); // 1000 dependencies

        final JsonArray json = parseJsonArray(response);
        assertThat(json).hasSize(100); // Default page size is 100
    }

    @Test
    public void getOutdatedComponentsTest() throws MalformedPackageURLException {
        final Project project = prepareProject();

        final Response response = target(V1_COMPONENT + "/project/" + project.getUuid())
                .queryParam("onlyOutdated", true)
                .queryParam("onlyDirect", false)
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_OK);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("200"); // 200 outdated dependencies,  direct and transitive

        final JsonArray json = parseJsonArray(response);
        assertThat(json).hasSize(100); // Default page size is 100
    }

    @Test
    public void getOutdatedDirectComponentsTest() throws MalformedPackageURLException {
        final Project project = prepareProject();

        final Response response = target(V1_COMPONENT + "/project/" + project.getUuid())
                .queryParam("onlyOutdated", true)
                .queryParam("onlyDirect", true)
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_OK);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("75"); // 75 outdated direct dependencies

        final JsonArray json = parseJsonArray(response);
        assertThat(json).hasSize(75);
    }

    @Test
    public void getAllDirectComponentsTest() throws MalformedPackageURLException {
        final Project project = prepareProject();

        final Response response = target(V1_COMPONENT + "/project/" + project.getUuid())
                .queryParam("onlyDirect", true)
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_OK);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("100"); // 100 direct dependencies

        final JsonArray json = parseJsonArray(response);
        assertThat(json).hasSize(100);
    }

    @Test
    public void getAllComponentsFilterTest() {
        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var componentA = new Component();
        componentA.setProject(project);
        componentA.setName("Acme-Lib-A");
        qm.persist(componentA);

        final var componentB = new Component();
        componentB.setProject(project);
        componentB.setName("aCme-lIb-b");
        qm.persist(componentB);

        final var componentC = new Component();
        componentC.setProject(project);
        componentC.setName("somethingCompletelyDifferent");
        qm.persist(componentC);

        final Response response = target(V1_COMPONENT + "/project/" + project.getUuid())
                .queryParam("searchText", "ACME")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_OK);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("2");
        assertThat(parseJsonArray(response)).satisfiesExactly(
                component -> assertThat(component.asJsonObject().getString("name")).isEqualTo("Acme-Lib-A"),
                component -> assertThat(component.asJsonObject().getString("name")).isEqualTo("aCme-lIb-b")
        );
    }

    private Project prepareProject() throws MalformedPackageURLException {
        final Project project = qm.createProject("Acme Application", null, null, null, null, null, true, false);
        final List<String> directDepencencies = new ArrayList<>();
        // Generate 1000 dependencies
        for (int i = 0; i < 1000; i++) {
            Component component = new Component();
            component.setProject(project);
            component.setGroup("component-group");
            component.setName("component-name-" + i);
            component.setVersion(String.valueOf(i) + ".0");
            component.setPurl(new PackageURL(RepositoryType.MAVEN.toString(), "component-group", "component-name-" + i, String.valueOf(i) + ".0", null, null));
            component = qm.createComponent(component, false);
            // direct depencencies
            if (i < 100) {
                // 100 direct depencencies, 900 transitive depencencies
                directDepencencies.add("{\"uuid\":\"" + component.getUuid() + "\"}");
            }
            // Recent & Outdated
            if ((i >= 25) && (i < 225)) {
                // 100 outdated components, 75 of these are direct dependencies, 25 transitive
                final var metaComponent = new RepositoryMetaComponent();
                metaComponent.setRepositoryType(RepositoryType.MAVEN);
                metaComponent.setNamespace("component-group");
                metaComponent.setName("component-name-" + i);
                metaComponent.setLatestVersion(String.valueOf(i + 1) + ".0");
                metaComponent.setLastCheck(new Date());
                qm.persist(metaComponent);
            } else if (i < 500) {
                // 300 recent components, 25 of these are direct dependencies
                final var metaComponent = new RepositoryMetaComponent();
                metaComponent.setRepositoryType(RepositoryType.MAVEN);
                metaComponent.setNamespace("component-group");
                metaComponent.setName("component-name-" + i);
                metaComponent.setLatestVersion(String.valueOf(i) + ".0");
                metaComponent.setLastCheck(new Date());
                qm.persist(metaComponent);
            } else {
                // 500 components with no RepositoryMetaComponent containing version
                // metadata, all transitive dependencies
            }
        }
        project.setDirectDependencies("[" + String.join(",", directDepencencies.toArray(new String[0])) + "]");
        return project;
    }

    protected JsonArray parseJsonArray(Response response) {
        StringReader stringReader = new StringReader(response.readEntity(String.class));
        try (JsonReader jsonReader = Json.createReader(stringReader)) {
            return jsonReader.readArray();
        }
    }
}
