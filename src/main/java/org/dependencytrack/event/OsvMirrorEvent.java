package org.dependencytrack.event;

import alpine.event.framework.Event;

/**
 * Defines an event used to start a mirror of Google OSV.
 */
public record OsvMirrorEvent(String ecosystem) implements Event {
}