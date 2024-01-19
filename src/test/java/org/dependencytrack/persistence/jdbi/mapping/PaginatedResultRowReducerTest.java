package org.dependencytrack.persistence.jdbi.mapping;

import alpine.persistence.PaginatedResult;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Project;
import org.jdbi.v3.core.Jdbi;
import org.jdbi.v3.core.mapper.MappingException;
import org.jdbi.v3.freemarker.FreemarkerEngine;
import org.jdbi.v3.sqlobject.SqlObjectPlugin;
import org.jdbi.v3.sqlobject.customizer.Define;
import org.jdbi.v3.sqlobject.statement.SqlQuery;
import org.jdbi.v3.sqlobject.statement.UseRowReducer;
import org.junit.Before;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.dependencytrack.persistence.jdbi.JdbiTestUtil.createLocalVanillaJdbi;

public class PaginatedResultRowReducerTest extends PersistenceCapableTest {

    public static final class StringPaginatedResultRowReducer extends PaginatedResultRowReducer<String> {

        public StringPaginatedResultRowReducer() {
            super(String.class);
        }

    }

    public interface TestDao {

        @SqlQuery("""
                SELECT "NAME", COUNT(*) OVER () AS "totalCount" FROM "PROJECT"
                <#if limit??>
                LIMIT ${limit}
                </#if>
                """)
        @UseRowReducer(StringPaginatedResultRowReducer.class)
        PaginatedResult getProjectNamesPage(@Define Integer limit);

        @SqlQuery("SELECT \"NAME\" FROM \"PROJECT\"")
        @UseRowReducer(StringPaginatedResultRowReducer.class)
        PaginatedResult getProjectNamesPageWithoutTotalCount();

    }

    private Jdbi jdbi;

    @Before
    public void setUp() {
        jdbi = createLocalVanillaJdbi(qm)
                .installPlugin(new SqlObjectPlugin())
                .setTemplateEngine(FreemarkerEngine.instance())
                .registerRowMapper(String.class, (rs, ctx) -> rs.getString("NAME"));

        for (int i = 0; i < 10; i++) {
            final var project = new Project();
            project.setName("project-" + i);
            qm.persist(project);
        }
    }

    @Test
    public void testWithoutLimit() {
        final PaginatedResult result = jdbi.withExtension(TestDao.class,
                dao -> dao.getProjectNamesPage(null));

        assertThat(result.getTotal()).isEqualTo(10);
        assertThat(result.getObjects()).hasSize(10);
    }

    @Test
    public void testWithLimit() {
        final PaginatedResult result = jdbi.withExtension(TestDao.class,
                dao -> dao.getProjectNamesPage(5));

        assertThat(result.getTotal()).isEqualTo(10);
        assertThat(result.getObjects()).hasSize(5);
    }

    @Test
    public void testWithoutTotalCountColumn() {
        assertThatExceptionOfType(MappingException.class)
                .isThrownBy(() -> jdbi.useExtension(TestDao.class,
                        TestDao::getProjectNamesPageWithoutTotalCount));
    }

}