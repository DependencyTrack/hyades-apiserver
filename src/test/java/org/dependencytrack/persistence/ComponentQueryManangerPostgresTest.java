package org.dependencytrack.persistence;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import org.dependencytrack.AbstractPostgresEnabledTest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.RepositoryMetaComponent;
import org.dependencytrack.model.RepositoryType;
import org.junit.Test;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

public class ComponentQueryManangerPostgresTest extends AbstractPostgresEnabledTest {

    @Test
    public void testGetAllComponents() throws MalformedPackageURLException {

        final Project project = prepareProject();
        var components = qm.getComponents(project, false, false, false);
        assertThat(components.getTotal()).isEqualTo(1000);
    }

    @Test
    public void testGetOutdatedComponents() throws MalformedPackageURLException {

        final Project project = prepareProject();
        var components = qm.getComponents(project, false, true, false);
        assertThat(components.getTotal()).isEqualTo(200);
    }

    @Test
    public void testGetDirectComponents() throws MalformedPackageURLException {

        final Project project = prepareProject();
        var components = qm.getComponents(project, false, false, true);
        assertThat(components.getTotal()).isEqualTo(100);
    }

    @Test
    public void testGetOutdatedDirectComponents() throws MalformedPackageURLException {

        final Project project = prepareProject();
        var components = qm.getComponents(project, false, true, true);
        assertThat(components.getTotal()).isEqualTo(75);
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
}
