package org.dependencytrack.persistence.jdbi.mapping;

import org.dependencytrack.model.Finding;

public class FindingPaginatedResultRowReducer extends PaginatedResultRowReducer<Finding> {

    public FindingPaginatedResultRowReducer() {
        super(Finding.class);
    }

}
