package org.dependencytrack.persistence;

import alpine.persistence.OrderDirection;
import alpine.resources.AlpineRequest;

public record Ordering(String by, OrderDirection direction) {

    public Ordering(final AlpineRequest alpineRequest) {
        this(alpineRequest.getOrderBy(), alpineRequest.getOrderDirection());
    }

}
