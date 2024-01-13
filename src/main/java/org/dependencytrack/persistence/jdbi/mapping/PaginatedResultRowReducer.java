package org.dependencytrack.persistence.jdbi.mapping;

import alpine.persistence.PaginatedResult;
import org.jdbi.v3.core.result.RowReducer;
import org.jdbi.v3.core.result.RowView;
import org.jdbi.v3.core.result.UnableToProduceResultException;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

public class PaginatedResultRowReducer<T> implements RowReducer<PaginatedResultRowReducer.ResultContainer<T>, PaginatedResult> {

    public static final class ResultContainer<T> {

        private long totalCount;
        private final List<T> results = new ArrayList<>();

        private void addResult(final T result) {
            results.add(result);
        }

    }

    private final Class<T> elementClass;

    public PaginatedResultRowReducer(final Class<T> elementClass) {
        this.elementClass = elementClass;
    }

    @Override
    public ResultContainer<T> container() {
        return new ResultContainer<>();
    }

    @Override
    public void accumulate(final ResultContainer<T> container, final RowView rowView) {
        final Long totalCount = rowView.getColumn("totalCount", Long.class);
        if (totalCount == null) {
            throw new UnableToProduceResultException("Result does not contain a totalCount column");
        }

        container.totalCount = totalCount;
        container.addResult(rowView.getRow(elementClass));
    }

    @Override
    public Stream<PaginatedResult> stream(final ResultContainer<T> container) {
        return Stream.of(new PaginatedResult().objects(container.results).total(container.totalCount));
    }

}
