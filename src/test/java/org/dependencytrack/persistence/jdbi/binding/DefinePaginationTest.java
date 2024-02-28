package org.dependencytrack.persistence.jdbi.binding;

import alpine.persistence.Pagination;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Project;
import org.jdbi.v3.core.Jdbi;
import org.jdbi.v3.freemarker.FreemarkerEngine;
import org.jdbi.v3.sqlobject.SqlObjectPlugin;
import org.jdbi.v3.sqlobject.statement.SqlQuery;
import org.junit.Before;
import org.junit.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.jdbi;

public class DefinePaginationTest extends PersistenceCapableTest {

    public interface TestDao {

        @SqlQuery("SELECT \"NAME\" FROM \"PROJECT\" ORDER BY \"ID\" ${offsetAndLimit!}")
        List<String> getProjectNames(@DefinePagination Pagination pagination);

    }

    private Jdbi jdbi;

    @Before
    public void setUp() {
        jdbi = jdbi(qm)
                .installPlugin(new SqlObjectPlugin())
                .setTemplateEngine(FreemarkerEngine.instance());

        for (int i = 0; i < 66; i++) {
            final var project = new Project();
            project.setName("project-" + i);
            qm.persist(project);
        }
    }

    @Test
    public void testWithNullPagination() {
        final List<String> projectNames = jdbi.withExtension(TestDao.class,
                dao -> dao.getProjectNames(null));
        assertThat(projectNames).hasSize(66);
    }

    @Test
    public void testWithUnspecifiedPagination() {
        final List<String> projectNames = jdbi.withExtension(TestDao.class,
                dao -> dao.getProjectNames(new Pagination(Pagination.Strategy.NONE, 0, 0)));
        assertThat(projectNames).hasSize(66);
    }

    @Test
    public void testWithValidPagination() {
        final var pagination = new Pagination(Pagination.Strategy.PAGES, 2, 50);
        final List<String> projectNames = jdbi.withExtension(TestDao.class,
                dao -> dao.getProjectNames(pagination));

        assertThat(projectNames).hasSize(16);
        assertThat(projectNames.get(0)).isEqualTo("project-50");
        assertThat(projectNames.get(15)).isEqualTo("project-65");
    }

}
