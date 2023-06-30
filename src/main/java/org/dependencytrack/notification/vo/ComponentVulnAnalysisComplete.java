package org.dependencytrack.notification.vo;

import org.dependencytrack.model.Component;
import org.dependencytrack.model.Vulnerability;

import java.util.List;

public class ComponentVulnAnalysisComplete {
    private final List<Vulnerability> vulnerabilityList;
    private final Component component;

    public ComponentVulnAnalysisComplete(List<Vulnerability> vulnerabilityList, Component component) {
        this.vulnerabilityList = vulnerabilityList;
        this.component = component;
    }

    public List<Vulnerability> getVulnerabilityList() {
        return vulnerabilityList;
    }

    public Component getComponent() {
        return this.component;
    }
}
