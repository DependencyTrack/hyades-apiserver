package org.dependencytrack.persistence.jdbi.binding;

import alpine.persistence.OrderDirection;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Project;
import org.dependencytrack.persistence.Ordering;
import org.jdbi.v3.core.Jdbi;
import org.jdbi.v3.freemarker.FreemarkerEngine;
import org.jdbi.v3.sqlobject.SqlObjectPlugin;
import org.jdbi.v3.sqlobject.statement.SqlQuery;
import org.junit.Before;
import org.junit.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.dependencytrack.persistence.jdbi.JdbiTestUtil.createLocalVanillaJdbi;

public class DefineOrderingTest extends PersistenceCapableTest {

    public interface TestDao {

        @SqlQuery("SELECT \"ID\" AS \"id\", \"NAME\" AS \"nameAlias\" FROM \"PROJECT\" ${ordering!}")
        List<Project> getProjects(@DefineOrdering(allowedColumns = "nameAlias") Ordering ordering);

        @SqlQuery("SELECT \"ID\" AS \"id\", \"NAME\" AS \"nameAlias\" FROM \"PROJECT\" ${ordering!}")
        List<Project> getProjectsWithOrderingAlsoById(@DefineOrdering(allowedColumns = {"id", "nameAlias"}, alsoBy = "id DESC") Ordering ordering);

    }

    private Jdbi jdbi;
    private final Map<String, Long> projectIdsByName = new HashMap<>();

    @Before
    public void setUp() {
        jdbi = createLocalVanillaJdbi(qm)
                .installPlugin(new SqlObjectPlugin())
                .setTemplateEngine(FreemarkerEngine.instance())
                .registerRowMapper(Project.class, (rs, ctx) -> {
                    final var project = new Project();
                    project.setId(rs.getLong("id"));
                    project.setName(rs.getString("nameAlias"));
                    return project;
                });

        for (int i = 0; i < 5; i++) {
            final var project = new Project();
            project.setName("project-" + i);
            qm.persist(project);

            projectIdsByName.put(project.getName(), project.getId());
        }
    }

    @Test
    public void testWithNullOrdering() {
        final List<Project> projects = jdbi.withExtension(TestDao.class, dao -> dao.getProjects(null));
        assertThat(projects).extracting(Project::getName).containsExactlyInAnyOrder(
                "project-0",
                "project-1",
                "project-2",
                "project-3",
                "project-4"
        );
    }

    @Test
    public void testWithDisallowedColumn() {
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> jdbi.useExtension(TestDao.class,
                        dao -> dao.getProjects(new Ordering("NAME", OrderDirection.ASCENDING))));
    }

    @Test
    public void testWithOrderDirectionAscending() {
        final List<Project> projects = jdbi.withExtension(TestDao.class,
                dao -> dao.getProjects(new Ordering("nameAlias", OrderDirection.ASCENDING)));

        assertThat(projects).extracting(Project::getName).containsExactly(
                "project-0",
                "project-1",
                "project-2",
                "project-3",
                "project-4"
        );
    }

    @Test
    public void testWithOrderDirectionDescending() {
        final List<Project> projects = jdbi.withExtension(TestDao.class,
                dao -> dao.getProjects(new Ordering("nameAlias", OrderDirection.DESCENDING)));

        assertThat(projects).extracting(Project::getName).containsExactly(
                "project-4",
                "project-3",
                "project-2",
                "project-1",
                "project-0"
        );
    }

    @Test
    public void testWithOrderDirectionUnspecified() {
        final List<Project> projects = jdbi.withExtension(TestDao.class,
                dao -> dao.getProjects(new Ordering("nameAlias", OrderDirection.UNSPECIFIED)));

        assertThat(projects).extracting(Project::getName).containsExactly(
                "project-0",
                "project-1",
                "project-2",
                "project-3",
                "project-4"
        );
    }

    @Test
    public void testWithOrderingAlsoBy() {
        final var duplicateProjectIdsByName = new HashMap<String, Long>();
        for (int i = 0; i < 2; i++) {
            final var project = new Project();
            project.setName("project-" + i);
            qm.persist(project);

            duplicateProjectIdsByName.put(project.getName(), project.getId());
        }
        assertThat(qm.getCount(Project.class)).isEqualTo(7);

        final List<Project> projects = jdbi.withExtension(TestDao.class,
                dao -> dao.getProjectsWithOrderingAlsoById(new Ordering("nameAlias", OrderDirection.ASCENDING)));
        assertThat(projects).satisfiesExactly(
                project -> {
                    assertThat(project.getId()).isEqualTo(duplicateProjectIdsByName.get("project-0"));
                    assertThat(project.getName()).isEqualTo("project-0");
                },
                project -> {
                    assertThat(project.getId()).isEqualTo(projectIdsByName.get("project-0"));
                    assertThat(project.getName()).isEqualTo("project-0");
                },
                project -> {
                    assertThat(project.getId()).isEqualTo(duplicateProjectIdsByName.get("project-1"));
                    assertThat(project.getName()).isEqualTo("project-1");
                },
                project -> {
                    assertThat(project.getId()).isEqualTo(projectIdsByName.get("project-1"));
                    assertThat(project.getName()).isEqualTo("project-1");
                },
                project -> {
                    assertThat(project.getId()).isEqualTo(projectIdsByName.get("project-2"));
                    assertThat(project.getName()).isEqualTo("project-2");
                },
                project -> {
                    assertThat(project.getId()).isEqualTo(projectIdsByName.get("project-3"));
                    assertThat(project.getName()).isEqualTo("project-3");
                },
                project -> {
                    assertThat(project.getId()).isEqualTo(projectIdsByName.get("project-4"));
                    assertThat(project.getName()).isEqualTo("project-4");
                }
        );
    }

}
