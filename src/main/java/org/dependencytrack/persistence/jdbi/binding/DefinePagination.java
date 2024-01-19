package org.dependencytrack.persistence.jdbi.binding;

import alpine.persistence.Pagination;
import org.jdbi.v3.sqlobject.customizer.SqlStatementCustomizerFactory;
import org.jdbi.v3.sqlobject.customizer.SqlStatementCustomizingAnnotation;
import org.jdbi.v3.sqlobject.customizer.SqlStatementParameterCustomizer;

import java.lang.annotation.Annotation;
import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.lang.reflect.Type;

/**
 * Defines an {@code offsetAndLimit} template variable according to the annotated {@link Pagination} object.
 * <p>
 * A {@link Pagination} initialized as {@code new Pagination(Strategy.PAGES, 2, 50)} will result
 * in the {@code offsetAndLimit} variable to be defined as {@code OFFSET 50 FETCH NEXT 50 ROWS ONLY}.
 * <p>
 * If the annotated {@link Pagination} is {@code null}, or {@link Pagination#isPaginated()} is {@code false},
 * the {@code offsetAndLimit} variable will <strong>not</strong> be defined.
 * It's recommended to use FreeMarker's default operator ({@code !}) to deal with this, for example:
 * {@code SELECT "FOO" FROM "BAR" ${offsetAndLimit!}}
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.PARAMETER)
@SqlStatementCustomizingAnnotation(DefinePagination.StatementCustomizerFactory.class)
public @interface DefinePagination {

    final class StatementCustomizerFactory implements SqlStatementCustomizerFactory {

        @Override
        public SqlStatementParameterCustomizer createForParameter(final Annotation annotation, final Class<?> sqlObjectType,
                                                                  final Method method, final Parameter param, final int index,
                                                                  final Type paramType) {
            return (statement, argument) -> {
                if (argument instanceof final Pagination pagination && pagination.isPaginated()) {
                    statement.define("offsetAndLimit", "OFFSET :offset FETCH NEXT :limit ROWS ONLY");
                    statement.bind("offset", pagination.getOffset());
                    statement.bind("limit", pagination.getLimit());
                }
            };
        }
    }

}
