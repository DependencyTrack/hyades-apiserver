package org.dependencytrack.event;

import alpine.event.framework.Event;
import alpine.event.framework.SingletonCapableEvent;

import java.util.UUID;

/**
 * Defines an {@link Event} used to trigger repository meta analysis of the entire portfolio.
 */
public final class PortfolioRepositoryMetaAnalysisEvent extends SingletonCapableEvent {

    public static final UUID CHAIN_IDENTIFIER = UUID.fromString("208343a5-48b1-4ca1-b649-0bdf49422b4e");

    public PortfolioRepositoryMetaAnalysisEvent() {
        setChainIdentifier(CHAIN_IDENTIFIER);
        setSingleton(true);
    }

}
