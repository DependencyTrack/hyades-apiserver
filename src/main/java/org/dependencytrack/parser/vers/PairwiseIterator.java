package org.dependencytrack.parser.vers;

import org.apache.commons.lang3.tuple.Pair;

import java.util.Iterator;
import java.util.Map;
import java.util.NoSuchElementException;

class PairwiseIterator<T> implements Iterator<Map.Entry<T, T>> {

    private final Iterator<T> delegate;
    private T current;
    private T next;

    PairwiseIterator(final Iterable<T> iterable) {
        this.delegate = iterable.iterator();
    }

    @Override
    public boolean hasNext() {
        return delegate.hasNext();
    }

    @Override
    public Pair<T, T> next() {
        if (!delegate.hasNext()) {
            throw new NoSuchElementException();
        }

        if (current == null) {
            current = delegate.next();
        }
        if (delegate.hasNext()) {
            next = delegate.next();
        }

        final var item = Pair.of(current, next);
        current = next;
        return item;
    }

}
