package org.dependencytrack.event;

import alpine.event.framework.SingletonCapableEvent;

import java.util.UUID;

public class PortfolioRepositoryMetaAnalysisEvent extends SingletonCapableEvent {

    private static final UUID CHAIN_IDENTIFIER = UUID.fromString("208343a5-48b1-4ca1-b649-0bdf49422b4e");

    public PortfolioRepositoryMetaAnalysisEvent() {
        setChainIdentifier(CHAIN_IDENTIFIER);
        setSingleton(true);
    }

}
